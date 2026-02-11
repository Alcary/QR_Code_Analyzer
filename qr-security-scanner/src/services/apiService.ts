// Replace this with your computer's local IP address
// You can find it by running 'ipconfig' (Windows) or 'ifconfig' (Mac/Linux) in your terminal
const API_URL = 'http://192.168.1.224:8000/api/v1'; 

export interface ScanResult {
  status: 'safe' | 'danger' | 'suspicious';
  message: string;
  details?: {
    final_url?: string;
    server?: string;
    ml_confidence?: number;
  };
}

export const scanURL = async (url: string): Promise<ScanResult> => {
  try {
    const response = await fetch(`${API_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Scan API Error:", error);
    // Fallback error result
    return {
      status: 'suspicious',
      message: 'Could not connect to security server. Check your network.',
    };
  }
};
