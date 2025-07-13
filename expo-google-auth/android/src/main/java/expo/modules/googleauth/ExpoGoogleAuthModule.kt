package expo.modules.googleauth

import android.app.Activity
import android.content.Intent
import android.content.IntentSender
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.identity.AuthorizationClient
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
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

class ExpoGoogleAuthModule : Module() {

    companion object {
        private const val YOUTUBE_AUTH_REQUEST_CODE = 1001
    }

    // --- Authorization Flow Helpers ---

    // Stores promise during the PendingIntent flow
    private var currentPromise: Promise? = null

    // Register for activity results
    override fun definition() = ModuleDefinition {
        Name("ExpoGoogleAuth")

        // Register for activity results
        OnActivityResult { activity, payload ->
            if (payload.requestCode == YOUTUBE_AUTH_REQUEST_CODE) {
                handleYoutubeAuthResult(activity, payload.resultCode, payload.data)
            }
        }

        // --- Google Authentication ---

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

        // --- Youtube Authorization ---

        AsyncFunction("authorizeYoutube") { scopes: List<String>, webClientId: String, promise: Promise ->
            Log.d("ExpoGoogleAuthModule", "=== Starting YouTube Authorization ===")
            Log.d("ExpoGoogleAuthModule", "Requested scopes: $scopes")
            Log.d("ExpoGoogleAuthModule", "Web client ID: $webClientId")
            
            val currentActivity = appContext.currentActivity
            if (currentActivity == null) {
                Log.e("ExpoGoogleAuthModule", "No current activity available")
                promise.reject(
                    "E_ACTIVITY_UNAVAILABLE",
                    "Activity is not available. Ensure a foreground activity exists.",
                    null
                )
                return@AsyncFunction
            }
            
            Log.d("ExpoGoogleAuthModule", "Current activity: $currentActivity")
            Log.d("ExpoGoogleAuthModule", "Activity class: ${currentActivity::class.java.name}")

            // Validate webClientId
            if (webClientId.isBlank()) {
                Log.e("ExpoGoogleAuthModule", "Empty or blank web client ID")
                promise.reject(
                    "E_INVALID_CLIENT_ID",
                    "Web client ID cannot be empty or blank.",
                    null
                )
                return@AsyncFunction
            }
            
            if (!webClientId.contains(".googleusercontent.com") && !webClientId.contains(".apps.googleusercontent.com")) {
                Log.w("ExpoGoogleAuthModule", "Web client ID doesn't seem to be a Google OAuth client ID: $webClientId")
            }

            val parsedScopes = parseToYoutubeScopes(scopes)
            Log.d("ExpoGoogleAuthModule", "Parsed scopes: $parsedScopes")
            
            if (parsedScopes.isEmpty()) {
                Log.e("ExpoGoogleAuthModule", "No valid scopes after parsing")
                promise.reject(
                    "E_INVALID_SCOPES",
                    "No valid scopes provided. Please provide at least one scope.",
                    null
                )
                return@AsyncFunction
            }

            val request = buildAuthorizationRequest(parsedScopes, webClientId)
            val client = Identity.getAuthorizationClient(currentActivity)

            Log.d("ExpoGoogleAuthModule", "Got authorization client: $client")

            // Launch the authorization flow
            try {
                Log.d("ExpoGoogleAuthModule", "Starting authorization with client.authorize()")
                client.authorize(request)
                    .addOnSuccessListener { authResult ->
                        Log.d("ExpoGoogleAuthModule", "Authorization request successful")
                        Log.d("ExpoGoogleAuthModule", "Auth result: $authResult")
                        Log.d("ExpoGoogleAuthModule", "Has resolution: ${authResult.hasResolution()}")
                        Log.d("ExpoGoogleAuthModule", "Server auth code: ${authResult.serverAuthCode}")
                        
                        if (authResult.hasResolution()) {
                            Log.d("ExpoGoogleAuthModule", "Authorization has resolution - launching resolution")
                            launchAuthorizationResolution(authResult, promise, currentActivity)
                        } else {
                            Log.d("ExpoGoogleAuthModule", "Authorization successful without resolution")
                            val serverCode = authResult.serverAuthCode
                            if (serverCode != null) {
                                Log.d("ExpoGoogleAuthModule", "Resolving with server code: $serverCode")
                                promise.resolve(serverCode)
                            } else {
                                Log.e("ExpoGoogleAuthModule", "Server auth code is null despite successful authorization")
                                promise.reject(
                                    "E_NO_AUTH_CODE",
                                    "Authorization succeeded but server auth code is null.",
                                    null
                                )
                            }
                        }
                    }
                    .addOnFailureListener { e ->
                        Log.e("ExpoGoogleAuthModule", "Authorization request failed", e)
                        promise.reject(
                            "E_AUTH_FAILED",
                            "Google authorization failed: ${e.message}",
                            e
                        )
                    }
            } catch (e: Exception) {
                Log.e("ExpoGoogleAuthModule", "Exception during authorization", e)
                promise.reject(
                    "E_AUTH_FAILED",
                    "Google authorization failed: ${e.message}",
                    e
                )
            }
        }

    }

    // --- Google Authentication ---

    private enum class GoogleSignInMode {
        SWIG, // Sign-in With Google
        GID   // Google ID
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

    // --- Youtube Authorization ---

    private enum class YoutubeScope {
        READ_ONLY,
        UPLOAD,
        MANAGE_ACCOUNT,
        DOWNLOAD,
        FORCE_SSL,
        PARTNER,
        PARTNER_CHANNEL_AUDIT,
        CHANNEL_MEMBERSHIPS_CREATOR,
        THIRD_PARTY_LINK_CREATOR
    }

    private val youTubeScopes = mapOf(
        YoutubeScope.READ_ONLY to Scope("https://www.googleapis.com/auth/youtube.readonly"),
        YoutubeScope.UPLOAD to Scope("https://www.googleapis.com/auth/youtube.upload"),
        YoutubeScope.MANAGE_ACCOUNT to Scope("https://www.googleapis.com/auth/youtube"),
        YoutubeScope.DOWNLOAD to Scope("https://www.googleapis.com/auth/youtube.download"),
        YoutubeScope.FORCE_SSL to Scope("https://www.googleapis.com/auth/youtube.force-ssl"),
        YoutubeScope.PARTNER to Scope("https://www.googleapis.com/auth/youtubepartner"),
        YoutubeScope.PARTNER_CHANNEL_AUDIT to Scope("https://www.googleapis.com/auth/youtubepartner-channel-audit"),
        YoutubeScope.CHANNEL_MEMBERSHIPS_CREATOR to Scope("https://www.googleapis.com/auth/youtube.channel-memberships.creator"),
        YoutubeScope.THIRD_PARTY_LINK_CREATOR to Scope("https://www.googleapis.com/auth/youtube.third-party-link.creator")
    )

    private fun parseToYoutubeScopes(scopes: List<Any>): List<Scope> {
        return scopes.mapNotNull { operation ->
            when (operation) {
                is YoutubeScope -> youTubeScopes[operation]
                is String -> YoutubeScope.entries.find { it.name == operation }?.let { youTubeScopes[it] }
                else -> null
            }
        }
    }

    private fun buildAuthorizationRequest(
        scopes: List<Scope>, serverClientId: String
    ): AuthorizationRequest {
        Log.d("ExpoGoogleAuthModule", "Building authorization request")
        Log.d("ExpoGoogleAuthModule", "Scopes: $scopes")
        Log.d("ExpoGoogleAuthModule", "Server client ID: $serverClientId")
        
        val request = AuthorizationRequest.builder()
            .setRequestedScopes(scopes)
            .requestOfflineAccess(serverClientId)
            .build()
            
        Log.d("ExpoGoogleAuthModule", "Authorization request built: $request")
        return request
    }

    private fun launchAuthorizationResolution(
        authResult: AuthorizationResult,
        promise: Promise,
        activity: Activity
    ) {
        Log.d("ExpoGoogleAuthModule", "launchAuthorizationResolution called")
        Log.d("ExpoGoogleAuthModule", "Activity: $activity")
        Log.d("ExpoGoogleAuthModule", "Activity class: ${activity::class.java.name}")
        Log.d("ExpoGoogleAuthModule", "Activity state - isFinishing: ${activity.isFinishing}, isDestroyed: ${activity.isDestroyed}")
        
        val pendingIntent = authResult.pendingIntent
        if (pendingIntent != null) {
            Log.d("ExpoGoogleAuthModule", "PendingIntent: $pendingIntent")
            Log.d("ExpoGoogleAuthModule", "PendingIntent creator package: ${pendingIntent.creatorPackage}")
            Log.d("ExpoGoogleAuthModule", "PendingIntent target package: ${pendingIntent.targetPackage}")
            
            // Check if there's already a pending authorization request
            if (currentPromise != null) {
                Log.w("ExpoGoogleAuthModule", "Another authorization request is already in progress")
                promise.reject(
                    "E_AUTH_IN_PROGRESS",
                    "Another authorization request is already in progress.",
                    null
                )
                return
            }
            
            currentPromise = promise
            try {
                Log.d("ExpoGoogleAuthModule", "Starting intent sender for result with request code: $YOUTUBE_AUTH_REQUEST_CODE")
                activity.startIntentSenderForResult(
                    pendingIntent.intentSender,
                    YOUTUBE_AUTH_REQUEST_CODE,
                    null,
                    0,
                    0,
                    0
                )
                Log.d("ExpoGoogleAuthModule", "Intent sender started successfully")
            } catch (e: IntentSender.SendIntentException) {
                Log.e("ExpoGoogleAuthModule", "Failed to start authorization intent", e)
                currentPromise = null
                promise.reject(
                    "E_INTENT_FAILED",
                    "Failed to start authorization intent: ${e.message}",
                    e
                )
            } catch (e: Exception) {
                Log.e("ExpoGoogleAuthModule", "Unexpected error starting authorization intent", e)
                currentPromise = null
                promise.reject(
                    "E_INTENT_FAILED",
                    "Unexpected error starting authorization intent: ${e.message}",
                    e
                )
            }
        } else {
            Log.e("ExpoGoogleAuthModule", "No pending intent found in authorization result")
            promise.reject("E_NO_PENDING_INTENT", "No pending intent found.", null)
        }
    }

    private fun handleYoutubeAuthResult(activity: Activity, resultCode: Int, data: Intent?) {
        val promise = currentPromise
        if (promise != null) {
            try {
                Log.d("ExpoGoogleAuthModule", "Handling YouTube auth result - resultCode: $resultCode")
                if (data != null) {
                    val extras = data.extras
                    Log.d("ExpoGoogleAuthModule", "Intent extras: $extras")
                    if (extras != null) {
                        for (key in extras.keySet()) {
                            Log.d("ExpoGoogleAuthModule", "Extra key: $key, value: ${extras.get(key)}")
                        }
                    }
                }
                
                if (resultCode == Activity.RESULT_OK) {
                    val finalResult = Identity.getAuthorizationClient(activity)
                        .getAuthorizationResultFromIntent(data)
                    val serverCode = finalResult?.serverAuthCode
                    if (serverCode != null) {
                        promise.resolve(serverCode)
                    } else {
                        promise.reject(
                            "E_NO_AUTH_CODE",
                            "Authorization completed but no server auth code returned.",
                            null
                        )
                    }
                } else {
                    // Check if the intent contains error information
                    var errorMessage = "Authorization flow was cancelled by the user."
                    var errorCode = "E_AUTH_CANCELLED"
                    
                    if (data != null) {
                        try {
                            // Try to get the authorization result to see if there's more specific error info
                            val authResult = Identity.getAuthorizationClient(activity)
                                .getAuthorizationResultFromIntent(data)
                            
                            // If we got a result but it's not OK, there might be an error
                            if (authResult != null) {
                                Log.d("ExpoGoogleAuthModule", "Got auth result from cancelled intent: $authResult")
                                errorMessage = "Authorization failed with result: $authResult"
                                errorCode = "E_AUTH_RESULT_ERROR"
                            }
                        } catch (e: Exception) {
                            Log.e("ExpoGoogleAuthModule", "Error parsing auth result from cancelled intent", e)
                            errorMessage = "Authorization failed: ${e.message}"
                            errorCode = "E_AUTH_PARSE_ERROR"
                        }
                        
                        // Also check for common error extras
                        val extras = data.extras
                        if (extras != null) {
                            val errorExtra = extras.getString("error")
                            val errorDescExtra = extras.getString("error_description")
                            if (errorExtra != null) {
                                errorMessage = "Authorization error: $errorExtra"
                                if (errorDescExtra != null) {
                                    errorMessage += " - $errorDescExtra"
                                }
                                errorCode = "E_AUTH_ERROR"
                            }
                        }
                    }
                    
                    Log.d("ExpoGoogleAuthModule", "Authorization cancelled - resultCode: $resultCode, errorMessage: $errorMessage")
                    promise.reject(errorCode, errorMessage, null)
                }
            } catch (e: Exception) {
                Log.e("ExpoGoogleAuthModule", "Error handling YouTube auth result", e)
                promise.reject(
                    "E_AUTH_RESULT_ERROR",
                    "Failed to process authorization result: ${e.message}",
                    e
                )
            } finally {
                // Always clean up the promise reference
                currentPromise = null
            }
        }
    }

}