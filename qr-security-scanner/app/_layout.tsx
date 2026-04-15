/**
 * Root layout. Wires Expo Router into a JS-based stack navigator for full
 * slide animation control, and renders the animated splash on first load.
 */

import { useEffect, useState } from "react";
import { Easing, StatusBar } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import * as SplashScreen from "expo-splash-screen";
import { withLayoutContext } from "expo-router";
import { ParamListBase } from "@react-navigation/native";
import {
  createStackNavigator,
  StackNavigationOptions,
  StackNavigationEventMap,
} from "@react-navigation/stack";
import type { StackNavigationState } from "@react-navigation/routers";
import ErrorBoundary from "../src/components/ErrorBoundary";
import AnimatedSplash from "../src/components/AnimatedSplash";

SplashScreen.preventAutoHideAsync();

// JS-based stack navigator wired into Expo Router for full animation control
const { Navigator } = createStackNavigator();

const Stack = withLayoutContext<
  StackNavigationOptions,
  typeof Navigator,
  StackNavigationState<ParamListBase>,
  StackNavigationEventMap
>(Navigator);

// Shared timing spec used for both open and close
const slideSpec = {
  animation: "timing" as const,
  config: {
    duration: 380,
    // Standard CSS ease-in-out cubic bezier
    easing: Easing.bezier(0.42, 0, 0.58, 1),
  },
};

const slideFromRight: StackNavigationOptions = {
  gestureEnabled: false,
  transitionSpec: { open: slideSpec, close: slideSpec },
  cardStyleInterpolator: ({ current, layouts }) => {
    // This screen slides in from the right
    const translateX = current.progress.interpolate({
      inputRange: [0, 1],
      outputRange: [layouts.screen.width, 0],
      extrapolate: "clamp",
    });
    // The screen behind slides slightly left (parallax) as this one enters
    const behindTranslateX = current.progress.interpolate({
      inputRange: [0, 1],
      outputRange: [0, -layouts.screen.width * 0.25],
      extrapolate: "clamp",
    });
    return {
      cardStyle: { transform: [{ translateX }] },
      nextCardStyle: { transform: [{ translateX: behindTranslateX }] },
    };
  },
};

export default function RootLayout() {
  const [showSplash, setShowSplash] = useState(true);

  useEffect(() => {
    SplashScreen.hideAsync();
  }, []);

  return (
    <GestureHandlerRootView style={{ flex: 1, backgroundColor: "#000000" }}>
      <ErrorBoundary>
        <StatusBar
          barStyle="light-content"
          backgroundColor="transparent"
          translucent
        />
        <Stack
          screenOptions={{
            headerShown: false,
            cardStyle: { backgroundColor: "#000000" },
          }}
        >
          <Stack.Screen name="index" />
          <Stack.Screen
            name="history"
            options={{
              ...slideFromRight,
              cardStyle: { backgroundColor: "#F5F5F7" },
            }}
          />
          <Stack.Screen
            name="history-detail"
            options={{
              ...slideFromRight,
              cardStyle: { backgroundColor: "#F5F5F7" },
            }}
          />
        </Stack>
        {showSplash && (
          <AnimatedSplash onFinish={() => setShowSplash(false)} />
        )}
      </ErrorBoundary>
    </GestureHandlerRootView>
  );
}
