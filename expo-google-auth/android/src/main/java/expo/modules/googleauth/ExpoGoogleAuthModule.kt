package expo.modules.googleauth

import android.app.Activity
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.lifecycle.lifecycleScope
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.launch
import java.security.SecureRandom
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.ClearCredentialStateRequest

class ExpoGoogleAuthModule : Module() {

    private enum class GoogleSignInMode {
        SWIG, // Sign-in With Google
        GID   // Google ID
    }

    override fun definition() = ModuleDefinition {
        Name("ExpoGoogleAuth")

        AsyncFunction("launchGoogleAuth") { modeString: String, webClientId: String, promise: Promise ->
            val currentActivity = appContext.currentActivity
            if (currentActivity == null) {
                promise.reject(
                    "E_ACTIVITY_UNAVAILABLE",
                    "Activity is not available. Ensure a foreground activity exists.",
                    null
                )
                return@AsyncFunction
            }

            val signInMode = when (modeString.uppercase()) {
                "SIWG" -> GoogleSignInMode.SWIG
                "GID" -> GoogleSignInMode.GID
                else -> {
                    promise.reject(
                        "E_INVALID_MODE",
                        "Invalid mode '$modeString'. Must be 'SIWG' or 'GID'.",
                        null
                    )
                    return@AsyncFunction
                }
            }

            val credentialManager = CredentialManager.create(currentActivity)
            val request: GetCredentialRequest = buildGetCredentialRequest(signInMode, webClientId)

            // Use the activity's lifecycle scope for the coroutine
            (currentActivity as? AppCompatActivity)?.lifecycleScope?.launch {
                try {
                    val response: GetCredentialResponse =
                        credentialManager.getCredential(currentActivity, request)
                    handleSignInResponse(response, promise)
                } catch (e: GetCredentialCancellationException) {
                    Log.e("ExpoGoogleAuthModule", "Sign-in failed (Cancelled by user)", e)
                    promise.reject("E_SIGN_IN_CANCELLED", "Google Sign-In was cancelled by the user.", e)
                } catch (e: Exception) {
                    Log.e("ExpoGoogleAuthModule", "Sign-in failed (Other)", e)
                    promise.reject("E_SIGN_IN_FAILED", "Google Sign-In failed: ${e.message}", e)
                }
            } ?: run {
                // If we can't get the lifecycleScope, report an error
                promise.reject(
                    "E_ACTIVITY_NOT_COMPATIBLE",
                    "Current activity is not an AppCompatActivity or does not support lifecycleScope.",
                    null
                )
            }
        }

        AsyncFunction("signOut") { promise: Promise ->
            val currentActivity = appContext.currentActivity
            if (currentActivity == null) {
                promise.reject(
                    "E_ACTIVITY_UNAVAILABLE",
                    "Activity is not available. Ensure a foreground activity exists.",
                    null
                )
                return@AsyncFunction
            }
            val credentialManager = CredentialManager.create(currentActivity)
            (currentActivity as? AppCompatActivity)?.lifecycleScope?.launch {
                try {
                    credentialManager.clearCredentialState(ClearCredentialStateRequest())
                    Log.i("ExpoGoogleAuthModule", "Successfully signed out")
                    promise.resolve(null)
                } catch (e: Exception) {
                    Log.e("ExpoGoogleAuthModule", "Signing out failed", e)
                    promise.reject("E_SIGN_OUT_FAILED", "Google Sign-Out failed: ${e.message}", e)
                }
            } ?: run {
                promise.reject(
                    "E_ACTIVITY_NOT_COMPATIBLE",
                    "Current activity is not an AppCompatActivity or does not support lifecycleScope.",
                    null
                )
            }
        }
    }

    private fun buildGetCredentialRequest(mode: GoogleSignInMode, serverClientId: String): GetCredentialRequest {
        val nonce = generateNonce()
        return when (mode) {
            GoogleSignInMode.SWIG -> {
                val signInWithGoogleOption: GetSignInWithGoogleOption =
                    GetSignInWithGoogleOption.Builder(serverClientId)
                        .setNonce(nonce)
                        .build()
                GetCredentialRequest.Builder().addCredentialOption(signInWithGoogleOption).build()
            }
            GoogleSignInMode.GID -> {
                val googleIdOption: GetGoogleIdOption = GetGoogleIdOption.Builder()
                    .setFilterByAuthorizedAccounts(false) // Set to false to allow new account selection if needed, true to only show authorized
                    .setServerClientId(serverClientId)
                    .setAutoSelectEnabled(true)
                    .setNonce(nonce)
                    .build()
                GetCredentialRequest.Builder().addCredentialOption(googleIdOption).build()
            }
        }
    }

    private fun handleSignInResponse(result: GetCredentialResponse, promise: Promise) {
        when (val credential = result.credential) {
            is CustomCredential -> {
                if (credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                    try {
                        val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                        val idToken = googleIdTokenCredential.idToken
                        Log.i("ExpoGoogleAuthModule", "idToken received successfully.")
                        promise.resolve(idToken)
                    } catch (e: GoogleIdTokenParsingException) {
                        Log.e("ExpoGoogleAuthModule", "Received an invalid google id token response", e)
                        promise.reject(
                            "E_INVALID_TOKEN_RESPONSE",
                            "Received an invalid Google ID token response: ${e.message}",
                            e
                        )
                    }
                } else {
                    Log.e("ExpoGoogleAuthModule", "Unexpected type of CustomCredential: ${credential.type}")
                    promise.reject(
                        "E_UNEXPECTED_CREDENTIAL_TYPE",
                        "Unexpected type of custom credential: ${credential.type}",
                        null
                    )
                }
            }
            else -> {
                Log.e("ExpoGoogleAuthModule", "Unexpected credential type received.")
                promise.reject(
                    "E_UNEXPECTED_CREDENTIAL_TYPE",
                    "Unexpected credential type received from Google Sign-In.",
                    null
                )
            }
        }
    }

    private fun generateNonce(): String {
        val sr = SecureRandom()
        val bytes = ByteArray(16)
        sr.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}