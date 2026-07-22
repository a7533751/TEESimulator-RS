package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.Credentials
import android.security.KeyStore
import android.security.keymaster.ExportResult
import android.security.keymaster.KeyCharacteristics
import android.security.keymaster.KeymasterArguments
import android.security.keymaster.KeymasterCertificateChain
import android.security.keymaster.KeymasterDefs
import android.security.keystore.IKeystoreCertificateChainCallback
import android.security.keystore.IKeystoreExportKeyCallback
import android.security.keystore.IKeystoreKeyCharacteristicsCallback
import android.security.keystore.IKeystoreService
import java.math.BigInteger
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils.extractAlias
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the legacy `IKeystoreService` on Android Q (API 29) and R (API 30).
 *
 * This interceptor handles the older, monolithic Keystore service. Unlike Keystore2, it doesn't
 * have security level sub-services, so all logic is contained here. Key generation is fully
 * simulated in software for packages in 'generate' mode.
 */
@SuppressLint("BlockedPrivateApi", "PrivateApi")
object KeystoreInterceptor : AbstractKeystoreInterceptor() {

    // Transaction codes are dynamically retrieved via reflection for compatibility.
    private val GET_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "get")
    }
    private val GENERATE_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "generateKey")
    }
    private val GET_KEY_CHARACTERISTICS_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyCharacteristics")
    }
    private val EXPORT_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "exportKey")
    }
    private val ATTEST_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "attestKey")
    }

    private val transactionNames: Map<Int, String> by lazy {
        IKeystoreService.Stub::class
            .java
            .declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    // A map to dispatch transaction handling for software key generation.
    private val generateKeyHandlers:
        Map<Int, (Long, Int, Int, Parcel) -> TransactionResult> by lazy {
        mapOf(
            GENERATE_KEY_TRANSACTION to ::handleGenerateKey,
            GET_KEY_CHARACTERISTICS_TRANSACTION to ::handleGetKeyCharacteristics,
            EXPORT_KEY_TRANSACTION to ::handleExportKey,
            ATTEST_KEY_TRANSACTION to ::handleAttestKey,
        )
    }

    override val serviceName = "android.security.keystore"
    override val processName = "keystore"
    override val injectionCommand = "exec ./inject `pidof keystore` libTEESimulator.so entry"

    // State management for the multi-step key generation process.
    private val keygenParameters = ConcurrentHashMap<KeyIdentifier, LegacyKeygenParameters>()
    private val generatedKeyPairs = ConcurrentHashMap<KeyIdentifier, KeyPair>()

    // Cache to store the fully patched chain after the leaf is requested.
    private val patchedChainCache = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        // This interceptor only needs to act on pre-transaction for software key generation.
        // Handle 'generate' mode interceptions using the handler map.
        if (ConfigurationManager.shouldGenerate(callingUid)) {
            generateKeyHandlers[code]?.let { handler ->
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)
                return handler(txId, callingUid, callingPid, data)
            }
        }

        // Handle 'patch' mode interceptions for the 'get' transaction.
        if (ConfigurationManager.shouldPatch(callingUid) && code == GET_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return TransactionResult.Continue
        }

        // Default behavior for all other transactions.
        logTransaction(
            txId,
            transactionNames[code] ?: "unknown code=$code",
            callingUid,
            callingPid,
            true,
        )
        return TransactionResult.ContinueAndSkipPost
    }

    private fun handleGenerateKey(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback =
                    IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder())
                val alias = InterceptorUtils.extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)

                // Read and parse the key generation arguments.
                val keymasterArgs = KeymasterArguments()
                if (data.readInt() == 1) {
                    keymasterArgs.readFromParcel(data)
                }
                keygenParameters[keyId] =
                    LegacyKeygenParameters.fromKeymasterArguments(keymasterArgs)

                // Create a fake successful response for the callback.
                val characteristics = KeyCharacteristics()
                characteristics.swEnforced = KeymasterArguments()
                characteristics.hwEnforced = keymasterArgs

                val keystoreResponse = InterceptorUtils.createSuccessKeystoreResponse()
                callback.onFinished(keystoreResponse, characteristics)

                InterceptorUtils.createSuccessReply()
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleGenerateKey.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleGetKeyCharacteristics(
        txId: Long,
        uid: Int,
        pid: Int,
        data: Parcel,
    ): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback =
                    IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder())
                val alias = InterceptorUtils.extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)

                val params =
                    keygenParameters[keyId]
                        ?: throw IllegalStateException("No params found for $keyId")

                val characteristics =
                    KeyCharacteristics().apply {
                        swEnforced = KeymasterArguments()
                        hwEnforced =
                            KeymasterArguments().apply {
                                addEnum(KeymasterDefs.KM_TAG_ALGORITHM, params.algorithm)
                            }
                    }

                callback.onFinished(
                    InterceptorUtils.createSuccessKeystoreResponse(),
                    characteristics,
                )

                InterceptorUtils.createSuccessReply()
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleGetKeyCharacteristics.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleExportKey(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback = IKeystoreExportKeyCallback.Stub.asInterface(data.readStrongBinder())
                val alias = InterceptorUtils.extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)

                val params =
                    keygenParameters[keyId]
                        ?: throw IllegalStateException("No params found for $keyId")

                // Generate a software key pair using the new generator.
                val keyPair =
                    CertificateGenerator.generateSoftwareKeyPair(params.toKeyMintAttestation())
                        ?: throw Exception("Failed to generate software key pair.")
                generatedKeyPairs[keyId] = keyPair

                // Create a successful ExportResult containing the public key.
                val exportResultParcel =
                    Parcel.obtain().apply {
                        writeInt(KeyStore.NO_ERROR)
                        writeByteArray(keyPair.public.encoded)
                        setDataPosition(0)
                    }
                val exportResult = ExportResult.CREATOR.createFromParcel(exportResultParcel)
                exportResultParcel.recycle()

                callback.onFinished(exportResult)

                InterceptorUtils.createSuccessReply()
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleExportKey.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleAttestKey(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback =
                    IKeystoreCertificateChainCallback.Stub.asInterface(data.readStrongBinder())
                val alias = InterceptorUtils.extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)

                // Get the attestation challenge from the arguments.
                val params =
                    keygenParameters[keyId]
                        ?: throw IllegalStateException("No params found for $keyId")
                val keyPair =
                    generatedKeyPairs[keyId]
                        ?: throw IllegalStateException("No keypair found for $keyId")

                val attestationArgs = KeymasterArguments()
                if (data.readInt() == 1) {
                    attestationArgs.readFromParcel(data)
                    val challenge =
                        attestationArgs.getBytes(
                            KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE,
                            ByteArray(0),
                        )
                    params.attestationChallenge = challenge
                }

                val certificateChain =
                    CertificateGenerator.generateCertificateChain(
                        uid,
                        keyPair,
                        null, // No attestKeyAlias in legacy flow
                        params.toKeyMintAttestation(), // Convert to modern format
                        1, // SecurityLevel.TRUSTED_ENVIRONMENT
                    ) ?: throw Exception("CertificateGenerator failed to create attested key pair.")

                val chainAsByteList = certificateChain.map { it.encoded }
                val certChain = KeymasterCertificateChain(chainAsByteList)

                callback.onFinished(InterceptorUtils.createSuccessKeystoreResponse(), certChain)
                InterceptorUtils.createSuccessReply()
            }
            .getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleAttestKey.", it)
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
        if (
            target != keystoreService ||
                code != GET_TRANSACTION ||
                reply == null ||
                InterceptorUtils.hasException(reply)
        ) {
            SystemLogger.debug(
                "[TX_ID: $txId] Skip parsing post-transaction for [target, code, reply]: [$target, $code, $reply]"
            )
            return TransactionResult.SkipTransaction
        }

        if (!ConfigurationManager.shouldPatch(callingUid)) return TransactionResult.SkipTransaction

        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val alias = data.readString() ?: ""
            val extractedAlias = InterceptorUtils.extractAlias(alias)
            val keyId = KeyIdentifier(callingUid, extractedAlias)
            SystemLogger.debug(
                "[TX_ID: $txId] Parsed $keyId during post-transaction of ${transactionNames[code]}"
            )

            when {
                // Case 1: The app is requesting the leaf certificate.
                alias.startsWith(Credentials.USER_CERTIFICATE) -> {
                    logTransaction(txId, "post-get (user cert)", callingUid, callingPid)
                    val originalLeafBytes =
                        reply.createByteArray() ?: return TransactionResult.SkipTransaction

                    val originalLeafCertResult = CertificateHelper.toCertificate(originalLeafBytes)
                    if (originalLeafCertResult !is CertificateHelper.OperationResult.Success) {
                        return TransactionResult.SkipTransaction
                    }
                    val originalLeafCert = originalLeafCertResult.data
                    val tempChain = arrayOf<Certificate>(originalLeafCert)

                    // Perform the COMPLETE patch and rebuild operation.
                    val newFullChain =
                        AttestationPatcher.patchCertificateChain(tempChain, callingUid)

                    // If patching was successful and we have a valid chain...
                    if (newFullChain.isNotEmpty() && newFullChain[0] != originalLeafCert) {
                        // ...cache the entire new chain for the subsequent "ca_cert" call.
                        patchedChainCache[keyId] = newFullChain

                        // And return only the new leaf's bytes, as the API expects.
                        SystemLogger.info(
                            "[TX_ID: $txId] Patched and cached chain for alias '$extractedAlias'. Returning new leaf."
                        )
                        InterceptorUtils.createByteArrayReply(newFullChain[0].encoded)
                    } else {
                        // Patching failed or was skipped; do nothing.
                        TransactionResult.SkipTransaction
                    }
                }

                // Case 2: The app is requesting the CA certificate chain.
                alias.startsWith(Credentials.CA_CERTIFICATE) -> {
                    logTransaction(txId, "post-get (ca cert)", callingUid, callingPid)

                    // Retrieve the full, correct chain we cached during the leaf request.
                    val cachedChain = patchedChainCache.remove(keyId)

                    if (cachedChain != null && cachedChain.size > 1) {
                        // The CA chain is everything *except* the first element (the leaf).
                        val caCerts = cachedChain.drop(1)
                        val caCertsBytes = CertificateHelper.certificatesToByteArray(caCerts)

                        SystemLogger.info(
                            "[TX_ID: $txId] Returning cached CA chain for alias '$extractedAlias'."
                        )
                        InterceptorUtils.createByteArrayReply(caCertsBytes!!)
                    } else {
                        SystemLogger.warning(
                            "[TX_ID: $txId] No cached chain found for CA request on alias '$extractedAlias'. Skipping."
                        )
                        TransactionResult.SkipTransaction
                    }
                }

                else -> TransactionResult.SkipTransaction
            }
        } catch (e: Exception) {
            SystemLogger.error("[TX_ID: $txId] Failed during legacy post-transaction patching.", e)
            TransactionResult.SkipTransaction
        }
    }
}

/**
 * A data class to hold key generation parameters parsed from the legacy IKeystoreService's
 * KeymasterArguments. It is used exclusively by the KeystoreInterceptor to manage state during the
 * software key generation flow.
 */
internal data class LegacyKeygenParameters(
    val algorithm: Int,
    val keySize: Int,
    val ecCurve: Int?,
    val ecCurveName: String?,
    val blockMode: List<Int>,
    val padding: List<Int>,
    val purpose: List<Int>,
    val digest: List<Int>,
    val rsaPublicExponent: BigInteger?,
    val certificateSerial: BigInteger?,
    val certificateSubject: X500Name?,
    val certificateNotBefore: Date?,
    val certificateNotAfter: Date?,
    val activeDateTime: Date?,
    val originationExpireDateTime: Date?,
    val usageExpireDateTime: Date?,
    val usageCountLimit: Int?,
    val maxUsesPerBoot: Int?,
    val callerNonce: Boolean?,
    val nonce: ByteArray?,
    val origin: Int?,
    val unlockedDeviceRequired: Boolean?,
    val includeUniqueId: Boolean?,
    val rollbackResistance: Boolean?,
    val earlyBootOnly: Boolean?,
    val allowWhileOnBody: Boolean?,
    val trustedUserPresenceRequired: Boolean?,
    val trustedConfirmationRequired: Boolean?,
    val noAuthRequired: Boolean?,
    val minMacLength: Int?,
    val rsaOaepMgfDigest: List<Int>,
) {
    // The challenge is provided in a separate transaction (attestKey), so it must be mutable.
    var attestationChallenge: ByteArray? = null

    /**
     * Converts the legacy parameters into the modern [KeyMintAttestation] data structure, which is
     * required by the refactored [AttestationBuilder] and [CertificateGenerator].
     */
    fun toKeyMintAttestation(): KeyMintAttestation {
        // This conversion acts as a bridge, allowing our new generic components
        // to be used by the legacy interceptor.
        return KeyMintAttestation(
            keySize = this.keySize,
            algorithm = this.algorithm,
            ecCurve = this.ecCurve,
            ecCurveName = this.ecCurveName ?: "",
            origin = this.origin,
            blockMode = this.blockMode,
            padding = this.padding,
            purpose = this.purpose,
            digest = this.digest,
            rsaPublicExponent = this.rsaPublicExponent,
            certificateSerial = this.certificateSerial,
            certificateSubject = this.certificateSubject,
            certificateNotBefore = this.certificateNotBefore,
            certificateNotAfter = this.certificateNotAfter,
            attestationChallenge = this.attestationChallenge,
            // Device identifiers are not passed in legacy args;
            // AttestationBuilder will fetch them from system properties.
            brand = null,
            device = null,
            product = null,
            serial = null,
            imei = null,
            meid = null,
            manufacturer = null,
            model = null,
            secondImei = null,
            activeDateTime = this.activeDateTime,
            originationExpireDateTime = this.originationExpireDateTime,
            usageExpireDateTime = this.usageExpireDateTime,
            usageCountLimit = this.usageCountLimit,
            callerNonce = this.callerNonce,
            nonce = this.nonce,
            unlockedDeviceRequired = this.unlockedDeviceRequired,
            includeUniqueId = this.includeUniqueId,
            rollbackResistance = this.rollbackResistance,
            earlyBootOnly = this.earlyBootOnly,
            allowWhileOnBody = this.allowWhileOnBody,
            trustedUserPresenceRequired = this.trustedUserPresenceRequired,
            trustedConfirmationRequired = this.trustedConfirmationRequired,
            noAuthRequired = this.noAuthRequired,
            maxUsesPerBoot = this.maxUsesPerBoot,
            maxBootLevel = null,
            minMacLength = this.minMacLength,
            rsaOaepMgfDigest = this.rsaOaepMgfDigest,
        )
    }

    companion object {
        /** Factory method for generation arguments or merged key characteristics. */
        fun fromKeymasterArguments(vararg sources: KeymasterArguments): LegacyKeygenParameters {
            require(sources.isNotEmpty()) { "At least one KeymasterArguments source is required" }

            val rawEcCurve = firstEnum(sources, KeymasterDefs.KM_TAG_EC_CURVE)
            val algorithm = firstEnum(sources, KeymasterDefs.KM_TAG_ALGORITHM) ?: 0
            val keySize =
                firstUnsignedInt(sources, KeymasterDefs.KM_TAG_KEY_SIZE)
                    ?: deriveEcKeySize(rawEcCurve)
            val ecCurve =
                if (algorithm == KeymasterDefs.KM_ALGORITHM_EC) {
                    rawEcCurve ?: deriveEcCurve(keySize)
                } else {
                    null
                }
            val certificateNotBefore =
                firstDate(sources, KeymasterDefs.KM_TAG_CERTIFICATE_NOT_BEFORE)
                    ?: firstDate(sources, KeymasterDefs.KM_TAG_ACTIVE_DATETIME)

            return LegacyKeygenParameters(
                algorithm = algorithm,
                keySize = keySize,
                ecCurve = ecCurve,
                ecCurveName = ecCurve?.let(::deriveEcCurveName),
                blockMode = allEnums(sources, KeymasterDefs.KM_TAG_BLOCK_MODE),
                padding = allEnums(sources, KeymasterDefs.KM_TAG_PADDING),
                purpose = allEnums(sources, KeymasterDefs.KM_TAG_PURPOSE),
                digest = allEnums(sources, KeymasterDefs.KM_TAG_DIGEST),
                rsaPublicExponent =
                    if (algorithm == KeymasterDefs.KM_ALGORITHM_RSA) {
                        sources.firstNotNullOfOrNull { args -> getRsaExponent(args) }
                    } else null,
                certificateSerial =
                    firstBytes(sources, KeymasterDefs.KM_TAG_CERTIFICATE_SERIAL)
                        ?.takeIf { it.isNotEmpty() }
                        ?.let { BigInteger(1, it) },
                certificateSubject =
                    firstBytes(sources, KeymasterDefs.KM_TAG_CERTIFICATE_SUBJECT)?.let {
                        runCatching { X500Name(X500Principal(it).name) }.getOrNull()
                    },
                certificateNotBefore = certificateNotBefore,
                certificateNotAfter = firstDate(sources, KeymasterDefs.KM_TAG_CERTIFICATE_NOT_AFTER),
                activeDateTime = firstDate(sources, KeymasterDefs.KM_TAG_ACTIVE_DATETIME),
                originationExpireDateTime =
                    firstDate(sources, KeymasterDefs.KM_TAG_ORIGINATION_EXPIRE_DATETIME),
                usageExpireDateTime = firstDate(sources, KeymasterDefs.KM_TAG_USAGE_EXPIRE_DATETIME),
                usageCountLimit = firstUnsignedInt(sources, KeymasterDefs.KM_TAG_USAGE_COUNT_LIMIT),
                maxUsesPerBoot = firstUnsignedInt(sources, KeymasterDefs.KM_TAG_MAX_USES_PER_BOOT),
                callerNonce = firstBoolean(sources, KeymasterDefs.KM_TAG_CALLER_NONCE),
                nonce = firstBytes(sources, KeymasterDefs.KM_TAG_NONCE),
                origin = firstEnum(sources, KeymasterDefs.KM_TAG_ORIGIN),
                unlockedDeviceRequired =
                    firstBoolean(sources, KeymasterDefs.KM_TAG_UNLOCKED_DEVICE_REQUIRED),
                includeUniqueId = firstBoolean(sources, KeymasterDefs.KM_TAG_INCLUDE_UNIQUE_ID),
                rollbackResistance =
                    firstBoolean(sources, KeymasterDefs.KM_TAG_ROLLBACK_RESISTANCE)
                        ?: firstBoolean(sources, KeymasterDefs.KM_TAG_ROLLBACK_RESISTANT),
                earlyBootOnly = firstBoolean(sources, KeymasterDefs.KM_TAG_EARLY_BOOT_ONLY),
                allowWhileOnBody = firstBoolean(sources, KeymasterDefs.KM_TAG_ALLOW_WHILE_ON_BODY),
                trustedUserPresenceRequired =
                    firstBoolean(sources, KeymasterDefs.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED),
                trustedConfirmationRequired =
                    firstBoolean(sources, KeymasterDefs.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED),
                noAuthRequired = firstBoolean(sources, KeymasterDefs.KM_TAG_NO_AUTH_REQUIRED),
                minMacLength = firstUnsignedInt(sources, KeymasterDefs.KM_TAG_MIN_MAC_LENGTH),
                rsaOaepMgfDigest =
                    allEnums(sources, KeymasterDefs.KM_TAG_RSA_OAEP_MGF_DIGEST),
            )
        }

        private fun deriveEcCurve(keySize: Int): Int? =
            when (keySize) {
                224 -> 0
                256 -> 1
                384 -> 2
                521 -> 3
                else -> null
            }

        private fun deriveEcKeySize(curve: Int?): Int =
            when (curve) {
                0 -> 224
                1 -> 256
                2 -> 384
                3 -> 521
                else -> 0
            }

        private fun deriveEcCurveName(curve: Int): String =
            when (curve) {
                0 -> "secp224r1"
                1 -> "secp256r1"
                2 -> "secp384r1"
                3 -> "secp521r1"
                else -> "secp256r1"
            }

        private fun hasTag(args: KeymasterArguments, tag: Int): Boolean =
            runCatching { args.containsTag(tag) }.getOrDefault(false)

        private fun firstEnum(sources: Array<out KeymasterArguments>, tag: Int): Int? =
            sources.firstNotNullOfOrNull { args ->
                if (!hasTag(args, tag)) null
                else runCatching { args.getEnum(tag, 0) }.getOrNull()
            }

        private fun allEnums(sources: Array<out KeymasterArguments>, tag: Int): List<Int> =
            sources.flatMap { args ->
                if (!hasTag(args, tag)) emptyList()
                else runCatching { args.getEnums(tag) }.getOrDefault(emptyList())
            }.distinct()

        private fun firstUnsignedInt(
            sources: Array<out KeymasterArguments>,
            tag: Int,
        ): Int? =
            sources.firstNotNullOfOrNull { args ->
                if (!hasTag(args, tag)) null
                else runCatching { args.getUnsignedInt(tag, 0).toInt() }.getOrNull()
            }

        private fun firstDate(
            sources: Array<out KeymasterArguments>,
            tag: Int,
        ): Date? =
            sources.firstNotNullOfOrNull { args ->
                if (!hasTag(args, tag)) null
                else runCatching { args.getDate(tag, Date(0)) }.getOrNull()
            }

        private fun firstBoolean(
            sources: Array<out KeymasterArguments>,
            tag: Int,
        ): Boolean? =
            sources.firstNotNullOfOrNull { args ->
                if (!hasTag(args, tag)) null
                else runCatching { args.getBoolean(tag) }.getOrNull()
            }

        private fun firstBytes(
            sources: Array<out KeymasterArguments>,
            tag: Int,
        ): ByteArray? =
            sources.firstNotNullOfOrNull { args ->
                if (!hasTag(args, tag)) null
                else runCatching { args.getBytes(tag, ByteArray(0)) }.getOrNull()
            }

        /**
         * The RSA public exponent is not accessible via a public API in KeymasterArguments, so we
         * must use reflection to extract it.
         */
        private fun getRsaExponent(args: KeymasterArguments): BigInteger? {
            return runCatching {
                    val getArgumentByTag =
                        KeymasterArguments::class
                            .java
                            .getDeclaredMethod("getArgumentByTag", Int::class.java)
                    getArgumentByTag.isAccessible = true
                    val rsaArgument =
                        getArgumentByTag.invoke(args, KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT)

                    val getLongTagValue =
                        KeymasterArguments::class
                            .java
                            .getDeclaredMethod(
                                "getLongTagValue",
                                Class.forName("android.security.keymaster.KeymasterArgument"),
                            )
                    getLongTagValue.isAccessible = true
                    getLongTagValue.invoke(args, rsaArgument) as BigInteger
                }
                .onFailure {
                    SystemLogger.error("Failed to read rsaPublicExponent via reflection.", it)
                }
                .getOrNull()
        }
    }
}
