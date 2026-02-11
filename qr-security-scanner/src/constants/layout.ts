import { Dimensions, Platform } from 'react-native';

const { width, height } = Dimensions.get('window');

export const SCREEN_WIDTH = width;
export const SCREEN_HEIGHT = height;

// Responsive calculations
export const SCAN_AREA_SIZE = Math.min(width * 0.7, 320);
export const CORNER_SIZE = SCAN_AREA_SIZE * 0.2; 
export const CORNER_BORDER_WIDTH = Math.max(4, SCAN_AREA_SIZE * 0.02); 
export const CORNER_RADIUS = CORNER_SIZE * 0.4;
export const BOTTOM_BUTTON_OFFSET = Platform.OS === 'ios' ? height * 0.08 : height * 0.11;