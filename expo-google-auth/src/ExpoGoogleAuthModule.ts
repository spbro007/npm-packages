import { NativeModule, requireNativeModule } from "expo";

export enum GoogleSignInMode {
  SWIG = "SWIG",
  GID = "GID",
}

export enum YoutubeScope {
  READ_ONLY = "READ_ONLY",
  UPLOAD = "UPLOAD",
  MANAGE_ACCOUNT = "MANAGE_ACCOUNT",
  DOWNLOAD = "DOWNLOAD",
  FORCE_SSL = "FORCE_SSL",
  PARTNER = "PARTNER",
  PARTNER_CHANNEL_AUDIT = "PARTNER_CHANNEL_AUDIT",
  CHANNEL_MEMBERSHIPS_CREATOR = "CHANNEL_MEMBERSHIPS_CREATOR",
  THIRD_PARTY_LINK_CREATOR = "THIRD_PARTY_LINK_CREATOR",
}

declare class ExpoGoogleAuthModule extends NativeModule {
  launchGoogleAuth(
    mode: GoogleSignInMode,
    webClientId: string
  ): Promise<string>;
  signOut(): Promise<void>;
  authorizeYoutube(
    scopes: YoutubeScope[],
    webClientId: string
  ): Promise<string>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoGoogleAuthModule>("ExpoGoogleAuth");
