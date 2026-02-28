import { Stack } from "expo-router";
import { StatusBar } from "react-native";
import ErrorBoundary from "../src/components/ErrorBoundary";

export default function RootLayout() {
  return (
    <ErrorBoundary>
      <StatusBar
        barStyle="light-content"
        backgroundColor="transparent"
        translucent
      />
      <Stack
        screenOptions={{
          headerShown: false,
          contentStyle: { backgroundColor: "#000000" },
        }}
      >
        <Stack.Screen name="index" />
        <Stack.Screen
          name="history"
          options={{
            animation: "slide_from_right",
            contentStyle: { backgroundColor: "#F5F5F7" },
          }}
        />
        <Stack.Screen
          name="history-detail"
          options={{
            animation: "slide_from_right",
            contentStyle: { backgroundColor: "#F5F5F7" },
          }}
        />
      </Stack>
    </ErrorBoundary>
  );
}
