import { Alert, Linking } from "react-native";
import { isNativeActionError, type NativeActionError } from "./qrActions";

type NativeActionFallbackOptions = {
  error: unknown;
  title: string;
  permissionBody: string;
  blockedBody: string;
  unavailableBody: string;
  fallbackBody: string;
};

export function showNativeActionFallback({
  error,
  title,
  permissionBody,
  blockedBody,
  unavailableBody,
  fallbackBody,
}: NativeActionFallbackOptions) {
  if (!isNativeActionError(error)) {
    Alert.alert(title, fallbackBody);
    return;
  }

  if (error.code === "permission-denied") {
    showPermissionAlert(title, error, permissionBody, blockedBody);
    return;
  }

  if (error.code === "native-unavailable") {
    Alert.alert(title, unavailableBody);
    return;
  }

  Alert.alert(title, fallbackBody);
}

function showPermissionAlert(
  title: string,
  error: NativeActionError,
  permissionBody: string,
  blockedBody: string,
) {
  if (error.canAskAgain === false) {
    Alert.alert(title, blockedBody, [
      { text: "Not Now", style: "cancel" },
      { text: "Open Settings", onPress: () => Linking.openSettings() },
    ]);
    return;
  }

  Alert.alert(title, permissionBody);
}
