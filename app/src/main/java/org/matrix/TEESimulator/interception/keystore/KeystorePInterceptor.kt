package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.IKeystoreService
import android.security.KeyStore
import android.security.keymaster.KeyCharacteristics
import android.security.keymaster.KeymasterArguments
import android.security.keymaster.KeymasterBlob
import android.security.keymaster.KeymasterCertificateChain
import android.security.keymaster.KeymasterDefs
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils.extractAlias
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Android 9 (Pie) interceptor for the synchronous, pre-Q Keystore Binder contract.
 *
 * Pie's IKeystoreService does not use Q's callback objects. Key generation and normal crypto remain
 * on the real QTI service. Successful attestation chains are rebuilt with the configured keybox;
 * when QTI returns -10003, a replacement chain is synthesized around the exported hardware public
 * key. The private key always remains in the device Keystore.
 */
@SuppressLint("BlockedPrivateApi", "PrivateApi")
object KeystorePInterceptor : AbstractKeystoreInterceptor() {
    private const val QTI_ATTESTATION_FAILURE = -10003
    private const val MAX_CERTIFICATE_CHAIN_LENGTH = 16

    private val generateKeyTransaction by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "generateKey")
    }
    private val attestKeyTransaction by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "attestKey")
    }
    private val exportKeyTransaction by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "exportKey")
    }
    private val getKeyCharacteristicsTransaction by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyCharacteristics")
    }

    private val keygenParameters =
        ConcurrentHashMap<KeyIdentifier, LegacyKeygenParameters>()
    private val targetedAttestations = ConcurrentHashMap<Long, Int>()
    private val uidDelegationLock = ReentrantLock()

    override val serviceName = "android.security.keystore"
    override val processName = "keystore"
    override val injectionCommand = "exec ./inject `pidof keystore` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        intArrayOf(
            generateKeyTransaction,
            attestKeyTransaction,
            exportKeyTransaction,
            getKeyCharacteristicsTransaction,
        )
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val configUid =
            ConfigurationManager.resolveTargetUid(callingUid, callingPid)
                ?: return TransactionResult.ContinueAndSkipPost
        if (code == attestKeyTransaction) targetedAttestations[txId] = configUid

        return try {
            when (code) {
                generateKeyTransaction -> {
                    rememberGenerateRequest(callingUid, data)
                    logTransaction(txId, "generateKey", callingUid, callingPid, skipPost = true)
                }
                attestKeyTransaction ->
                    logTransaction(txId, "attestKey", callingUid, callingPid)
                else -> logTransaction(txId, "code=$code", callingUid, callingPid, skipPost = true)
            }
            if (code == attestKeyTransaction) TransactionResult.Continue
            else TransactionResult.ContinueAndSkipPost
        } catch (t: Throwable) {
            SystemLogger.warning("Pie transaction inspection failed; preserving post handling.", t)
            // Keep the post hook for attestKey so malformed requests still fail closed instead of
            // returning the vendor certificate chain unchanged.
            if (code == attestKeyTransaction) TransactionResult.Continue
            else TransactionResult.ContinueAndSkipPost
        }
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (code != attestKeyTransaction) {
            return TransactionResult.SkipTransaction
        }
        val configUid = targetedAttestations.remove(txId) ?: return TransactionResult.SkipTransaction
        if (reply == null) return TransactionResult.SkipTransaction

        return runCatching {
            reply.setDataPosition(0)
            reply.readException()
            val vendorResult = reply.readInt()

            val request = readAttestationRequest(data)
                ?: return@runCatching failClosedAttestation(
                    txId,
                    callingUid,
                    "could not parse the target attestKey request",
                )
            val rawAlias = request.rawAlias
            val alias = extractAlias(rawAlias)

            when (vendorResult) {
                KeyStore.NO_ERROR -> {
                    val originalChain = readCertificateChain(reply)
                    if (originalChain != null) {
                        val patchedChain =
                            AttestationPatcher.patchCertificateChain(
                                originalChain.toTypedArray(),
                                configUid,
                            )
                        if (isReplacementChain(originalChain, patchedChain.asList())) {
                            SystemLogger.info(
                                "[TX_ID: $txId] Replaced successful QTI Pie attestation for uid=$callingUid alias=$alias"
                            )
                            return@runCatching createAttestationReply(patchedChain.asList())
                        }
                        SystemLogger.warning(
                            "[TX_ID: $txId] QTI Pie chain patch returned the original chain; trying synthesis."
                        )
                    } else {
                        SystemLogger.warning(
                            "[TX_ID: $txId] Could not parse successful QTI Pie chain; trying synthesis."
                        )
                    }

                    val generatedChain =
                        generateFallbackChain(request, callingUid, configUid, callingPid)
                            ?: return@runCatching failClosedAttestation(
                                txId,
                                callingUid,
                                "successful QTI reply could not be replaced",
                            )
                    SystemLogger.info(
                        "[TX_ID: $txId] Replaced successful QTI Pie attestation by synthesis for uid=$callingUid alias=$alias"
                    )
                    createAttestationReply(generatedChain)
                }
                QTI_ATTESTATION_FAILURE -> {
                    val generatedChain =
                        generateFallbackChain(request, callingUid, configUid, callingPid)
                            ?: return@runCatching failClosedAttestation(
                                txId,
                                callingUid,
                                "QTI -10003 fallback could not create a chain",
                            )
                    SystemLogger.info(
                        "[TX_ID: $txId] Replaced QTI Pie attestation failure for uid=$callingUid alias=$alias"
                    )
                    createAttestationReply(generatedChain)
                }
                else -> TransactionResult.SkipTransaction
            }
        }.getOrElse {
            SystemLogger.warning(
                "[TX_ID: $txId] Pie attestation replacement failed; blocking the target reply.",
                it,
            )
            createAttestationErrorReply(QTI_ATTESTATION_FAILURE)
        }
    }

    private fun rememberGenerateRequest(uid: Int, source: Parcel) {
        source.setDataPosition(0)
        source.enforceInterface(IKeystoreService.DESCRIPTOR)
        val rawAlias = source.readString() ?: return
        val args = readArguments(source)
        keygenParameters[KeyIdentifier(uid, extractAlias(rawAlias))] =
            LegacyKeygenParameters.fromKeymasterArguments(args)
    }

    private fun readArguments(source: Parcel): KeymasterArguments {
        val args = KeymasterArguments()
        if (source.readInt() != 0) args.readFromParcel(source)
        return args
    }

    private fun readAttestationRequest(source: Parcel): AttestationRequest? = runCatching {
        source.setDataPosition(0)
        source.enforceInterface(IKeystoreService.DESCRIPTOR)
        val rawAlias = source.readString() ?: return@runCatching null
        AttestationRequest(rawAlias, readArguments(source))
    }.getOrNull()

    private fun readCertificateChain(source: Parcel): List<Certificate>? = runCatching {
        // The synchronous Pie AIDL reply writes an out-Parcelable presence marker first.
        if (source.readInt() == 0) return@runCatching null
        val certificateCount = source.readInt()
        if (certificateCount !in 1..MAX_CERTIFICATE_CHAIN_LENGTH) {
            SystemLogger.warning("Invalid Pie certificate chain length: $certificateCount")
            return@runCatching null
        }

        val certificates = ArrayList<Certificate>(certificateCount)
        repeat(certificateCount) {
            val encoded = source.createByteArray() ?: return@runCatching null
            val parsed = CertificateHelper.toCertificate(encoded)
            if (parsed !is CertificateHelper.OperationResult.Success) return@runCatching null
            certificates.add(parsed.data)
        }
        certificates
    }.getOrNull()

    private fun isReplacementChain(
        originalChain: List<Certificate>,
        replacementChain: List<Certificate>,
    ): Boolean =
        replacementChain.isNotEmpty() &&
            !replacementChain[0].encoded.contentEquals(originalChain[0].encoded)

    private fun generateFallbackChain(
        request: AttestationRequest,
        uid: Int,
        configUid: Int,
        pid: Int,
    ): List<Certificate>? {
        val alias = extractAlias(request.rawAlias)
        val keyId = KeyIdentifier(uid, alias)
        val params = loadKeyParameters(keyId, request.rawAlias, pid) ?: run {
            SystemLogger.warning("No captured Pie key parameters for uid=$uid alias=$alias")
            return null
        }
        val challenge =
            request.arguments.getBytes(
                KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE,
                ByteArray(0),
            )
        val attestation = params.toKeyMintAttestation().copy(attestationChallenge = challenge)

        val publicKey = exportPublicKey(request.rawAlias, uid, pid) ?: return null
        return CertificateGenerator.generateCertificateChain(
            configUid,
            KeyPair(publicKey, null),
            null,
            attestation,
            1,
        )
    }

    private fun loadKeyParameters(
        keyId: KeyIdentifier,
        rawAlias: String,
        pid: Int,
    ): LegacyKeygenParameters? {
        val characteristics = KeyCharacteristics()
        val empty = KeymasterBlob(ByteArray(0))
        val resultCode =
            uidDelegationLock.withLock {
                if (!prepareCallingUid(keyId.uid, pid, getKeyCharacteristicsTransaction)) {
                    return@withLock null
                }
                try {
                    KeyStore.getInstance().getKeyCharacteristics(
                        rawAlias,
                        empty,
                        empty,
                        keyId.uid,
                        characteristics,
                    )
                } finally {
                    clearCallingUid()
                }
            }
        if (resultCode == KeyStore.NO_ERROR) {
            val sources =
                listOfNotNull(characteristics.hwEnforced, characteristics.swEnforced)
                    .toTypedArray()
            if (sources.isNotEmpty()) {
                return runCatching {
                        LegacyKeygenParameters.fromKeymasterArguments(*sources)
                    }
                    .onSuccess { keygenParameters[keyId] = it }
                    .getOrNull()
            }
        }
        return keygenParameters[keyId]
    }

    private fun exportPublicKey(rawAlias: String, uid: Int, pid: Int) = runCatching {
        val empty = KeymasterBlob(ByteArray(0))
        val result = uidDelegationLock.withLock {
            if (!prepareCallingUid(uid, pid, exportKeyTransaction)) {
                SystemLogger.warning(
                    "Cannot prepare UID delegation for exportKey (uid=$uid pid=$pid code=$exportKeyTransaction)"
                )
                return@withLock null
            }
            try {
                KeyStore.getInstance().exportKey(
                    rawAlias,
                    KeymasterDefs.KM_KEY_FORMAT_X509,
                    empty,
                    empty,
                    uid,
                )
            } finally {
                clearCallingUid()
            }
        } ?: return@runCatching null
        if (result == null || result.resultCode != KeyStore.NO_ERROR) return@runCatching null
        val algorithm = if (result.exportData.firstOrNull() == 0x30.toByte()) {
            // X.509 SubjectPublicKeyInfo is self-describing; try EC first, then RSA.
            "EC"
        } else "RSA"
        runCatching {
            KeyFactory.getInstance(algorithm).generatePublic(X509EncodedKeySpec(result.exportData))
        }.getOrElse {
            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(result.exportData))
        }
    }.getOrNull()

    private fun createAttestationReply(chain: List<Certificate>): TransactionResult {
        val certificateChain = KeymasterCertificateChain(chain.map { it.encoded })
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeInt(KeyStore.NO_ERROR)
        // IKeystoreService.attestKey has an `out` Parcelable parameter. AIDL writes a non-null
        // marker before the KeymasterCertificateChain payload.
        parcel.writeInt(1)
        certificateChain.writeToParcel(parcel, 0)
        return TransactionResult.OverrideReply(parcel)
    }

    private fun failClosedAttestation(
        txId: Long,
        uid: Int,
        reason: String,
    ): TransactionResult {
        SystemLogger.error("[TX_ID: $txId] Blocking Pie attestation for uid=$uid: $reason")
        return createAttestationErrorReply(QTI_ATTESTATION_FAILURE)
    }

    private fun createAttestationErrorReply(errorCode: Int): TransactionResult {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeInt(errorCode)
        parcel.writeInt(0) // Null out-Parcelable marker: no certificate chain is exposed.
        return TransactionResult.OverrideReply(parcel)
    }

    private data class AttestationRequest(
        val rawAlias: String,
        val arguments: KeymasterArguments,
    )
}
