// Native Android source only. This file is never bundled into the browser
// frontend and provides no browser support or browser key-storage fallback.
package com.vaultx.transfer

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/** WorkManager entry point. Retry code must query Upload-Offset before sending. */
class VaultXBackgroundTransferWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        // Bind the real HTTP client here; never retry from a stale offset.
        return Result.failure()
    }
}

object VaultXSecureState {
    fun preferences(context: Context) = EncryptedSharedPreferences.create(
        context,
        "vaultx_transfer_state",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
