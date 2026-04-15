import { useEffect } from 'react';
import { StyleSheet, View, Text } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
  withTiming,
  withDelay,
  runOnJS,
  Easing,
} from 'react-native-reanimated';


// ─── Icon geometry constants ───────────────────────────────────────────────
// Tweak these if the proportions don't match the original icon closely enough.
const BLOCK = 70;       // corner square outer size
const GAP = 12;         // gap between the four quadrants
const INNER = 24;       // corner square inner hole size
const BR_OUTER = 16;    // corner square outer border radius
const BR_INNER = 6;     // corner square inner hole border radius

const DOT_LG = 30;      // large data dot size
const DOT_SM = 22;      // small data dot size
const DOT_GAP = 6;      // gap between data dots
const DOT_BR = 8;       // data dot border radius

// Orbital radius — how far each piece starts from its final position
const ORBIT_R = 180;
// cos/sin 45° — positions each piece on a diagonal from the centre
const D = ORBIT_R * 0.707;

// ─── Sub-components ────────────────────────────────────────────────────────

function CornerBlock() {
  return (
    <View style={styles.cornerOuter}>
      <View style={styles.cornerInner} />
    </View>
  );
}

function DataCluster() {
  return (
    <View style={styles.dataCluster}>
      <View style={styles.dataRow}>
        <View style={[styles.dot, styles.dotLg]} />
        <View style={[styles.dot, styles.dotLg]} />
      </View>
      <View style={styles.dataRow}>
        <View style={[styles.dot, styles.dotSm]} />
        <View style={[styles.dot, styles.dotSm]} />
      </View>
    </View>
  );
}

// ─── Main component ────────────────────────────────────────────────────────

interface Props {
  onFinish: () => void;
}

export default function AnimatedSplash({ onFinish }: Props) {
  // Each piece translates from its orbital start position to (0, 0).
  // Pieces start at opacity 1 so the white container is never empty when
  // the native splash dismisses — avoids a blank-screen flash.
  const tlX = useSharedValue(-D);
  const tlY = useSharedValue(-D);
  const trX = useSharedValue(D);
  const trY = useSharedValue(-D);
  const blX = useSharedValue(-D);
  const blY = useSharedValue(D);
  const brX = useSharedValue(D);
  const brY = useSharedValue(D);

  const textOpacity = useSharedValue(0);
  const textTranslateY = useSharedValue(14);
  const containerOpacity = useSharedValue(1);

  const spring = { damping: 14, stiffness: 95 };
  // ms between each piece flying in
  const STAGGER = 60;

  useEffect(() => {
    // Each piece springs into position from its orbital start, staggered
    tlX.value = withSpring(0, spring);
    tlY.value = withSpring(0, spring);

    trX.value = withDelay(STAGGER, withSpring(0, spring));
    trY.value = withDelay(STAGGER, withSpring(0, spring));

    blX.value = withDelay(STAGGER * 2, withSpring(0, spring));
    blY.value = withDelay(STAGGER * 2, withSpring(0, spring));

    brX.value = withDelay(STAGGER * 3, withSpring(0, spring));
    brY.value = withDelay(STAGGER * 3, withSpring(0, spring));

    // Title fades up after pieces have settled
    textOpacity.value = withDelay(850, withTiming(1, { duration: 500 }));
    textTranslateY.value = withDelay(850, withTiming(0, { duration: 500 }));

    // Fade out the entire splash
    containerOpacity.value = withDelay(
      2000,
      withTiming(0, { duration: 400, easing: Easing.out(Easing.ease) }, (finished) => {
        if (finished) runOnJS(onFinish)();
      }),
    );
  }, []);

  const tlStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: tlX.value }, { translateY: tlY.value }],
  }));
  const trStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: trX.value }, { translateY: trY.value }],
  }));
  const blStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: blX.value }, { translateY: blY.value }],
  }));
  const brStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: brX.value }, { translateY: brY.value }],
  }));
  const textStyle = useAnimatedStyle(() => ({
    opacity: textOpacity.value,
    transform: [{ translateY: textTranslateY.value }],
  }));
  const containerStyle = useAnimatedStyle(() => ({
    opacity: containerOpacity.value,
  }));

  return (
    <Animated.View style={[styles.container, containerStyle]}>
      <View style={styles.icon}>
        <View style={styles.row}>
          <Animated.View style={tlStyle}>
            <CornerBlock />
          </Animated.View>
          <Animated.View style={trStyle}>
            <CornerBlock />
          </Animated.View>
        </View>
        <View style={styles.row}>
          <Animated.View style={blStyle}>
            <CornerBlock />
          </Animated.View>
          <Animated.View style={brStyle}>
            <DataCluster />
          </Animated.View>
        </View>
      </View>

      <Animated.View style={[styles.textContainer, textStyle]}>
        <Text style={styles.title}>QR Security Scanner</Text>
      </Animated.View>
    </Animated.View>
  );
}

// ─── Styles ────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: '#FFFFFF',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 999,
  },
  icon: {
    gap: GAP,
  },
  row: {
    flexDirection: 'row',
    gap: GAP,
  },
  // Corner squares
  cornerOuter: {
    width: BLOCK,
    height: BLOCK,
    borderRadius: BR_OUTER,
    backgroundColor: '#000000',
    alignItems: 'center',
    justifyContent: 'center',
  },
  cornerInner: {
    width: INNER,
    height: INNER,
    borderRadius: BR_INNER,
    backgroundColor: '#FFFFFF',
  },
  // Data cluster (bottom-right quadrant)
  dataCluster: {
    width: BLOCK,
    height: BLOCK,
    gap: DOT_GAP,
    alignItems: 'center',
    justifyContent: 'center',
  },
  dataRow: {
    flexDirection: 'row',
    gap: DOT_GAP,
  },
  dot: {
    backgroundColor: '#000000',
    borderRadius: DOT_BR,
  },
  dotLg: {
    width: DOT_LG,
    height: DOT_LG,
  },
  dotSm: {
    width: DOT_SM,
    height: DOT_SM,
  },
  // Title
  textContainer: {
    marginTop: 44,
    alignItems: 'center',
  },
  title: {
    color: '#000000',
    fontSize: 22,
    fontWeight: '600',
    letterSpacing: 0.4,
  },
});
