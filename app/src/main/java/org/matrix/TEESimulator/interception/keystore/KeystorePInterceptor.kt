package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.IKeystoreService
import android.security.KeyStore
import android.security.keymaster.KeymasterArguments
import android.security.keymaster.KeymasterBlob
import android.security.keymaster.KeymasterCertificateChain
import android.security.keymaster.KeymasterDefs
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils.extractAlias
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator

/**
 * Android 9 (Pie) interceptor for the synchronous, pre-Q Keystore Binder contract.
 *
 * Pie's IKeystoreService does not use Q's callback objects. The first implementation therefore
 * leaves key generation and normal crypto on the real QTI service, and only replaces a failed
 * attestation response when the vendor returns -10003. The private key remains in the device
 * Keystore; only the certificate chain is synthesized.
 */
@SuppressLint("BlockedPrivateApi", "PrivateApi")
object KeystorePInterceptor : AbstractKeystoreInterceptor() {
    private const val QTI_ATTESTATION_FAILURE = -10003

    private val generateKeyTransaction by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "generateKey")
    }
    private val attestKeyTransaction by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "attestKey")
    }

    private val keygenParameters =
        ConcurrentHashMap<KeyIdentifier, LegacyKeygenParameters>()

    override val serviceName = "android.security.keystore"
    override val processName = "keystore"
    override val injectionCommand = "exec ./inject `pidof keystore` libTEESimulator.so entry"

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (!isTargeted(callingUid)) return TransactionResult.ContinueAndSkipPost

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
            // A malformed or vendor-specific transaction must always reach the real Keystore.
            SystemLogger.warning("Pie transaction inspection failed; forwarding unchanged.", t)
            TransactionResult.ContinueAndSkipPost
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
        if (code != attestKeyTransaction || reply == null || !isTargeted(callingUid)) {
            return TransactionResult.SkipTransaction
        }

        return runCatching {
            reply.setDataPosition(0)
            reply.readException()
            val vendorResult = reply.readInt()
            if (vendorResult != QTI_ATTESTATION_FAILURE) {
                return@runCatching TransactionResult.SkipTransaction
            }

            data.setDataPosition(0)
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val rawAlias = data.readString() ?: return@runCatching TransactionResult.SkipTransaction
            val alias = extractAlias(rawAlias)
            val keyId = KeyIdentifier(callingUid, alias)
            val params = keygenParameters[keyId]
                ?: return@runCatching TransactionResult.SkipTransaction
            val attestationArgs = readArguments(data)
            params.attestationChallenge =
                attestationArgs.getBytes(
                    KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE,
                    ByteArray(0),
                )

            val publicKey = exportPublicKey(rawAlias, callingUid)
                ?: return@runCatching TransactionResult.SkipTransaction
            val subjectKeyPair = KeyPair(publicKey, null)
            val chain = CertificateGenerator.generateCertificateChain(
                callingUid,
                subjectKeyPair,
                null,
                params.toKeyMintAttestation(),
                1,
            ) ?: return@runCatching TransactionResult.SkipTransaction

            SystemLogger.info(
                "[TX_ID: $txId] Replaced QTI Pie attestation failure for uid=$callingUid alias=$alias"
            )
            createAttestationReply(chain)
        }.getOrElse {
            SystemLogger.warning(
                "[TX_ID: $txId] Pie attestation fallback failed; preserving QTI reply.",
                it,
            )
            TransactionResult.SkipTransaction
        }
    }

    private fun isTargeted(uid: Int): Boolean =
        ConfigurationManager.shouldPatch(uid) || ConfigurationManager.shouldGenerate(uid)

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

    private fun exportPublicKey(rawAlias: String, uid: Int) = runCatching {
        val empty = KeymasterBlob(ByteArray(0))
        val result = KeyStore.getInstance().exportKey(
            rawAlias,
            KeymasterDefs.KM_KEY_FORMAT_X509,
            empty,
            empty,
            uid,
        )
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

    private fun createAttestationReply(chain: List<java.security.cert.Certificate>): TransactionResult {
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
}
