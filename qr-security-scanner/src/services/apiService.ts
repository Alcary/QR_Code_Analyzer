// Replace this with your computer's local IP address
// You can find it by running 'ipconfig' (Windows) or 'ifconfig' (Mac/Linux) in your terminal
const API_URL = 'http://192.168.1.224:8000/api/v1';

// ── Response Interfaces ─────────────────────────────────────

export interface MLDetails {
  ensemble_score: number;
  xgb_score: number;
  bert_score: number;
  xgb_weight: number;
  dampened_score: number;
}

export interface DomainDetails {
  registered_domain: string;
  full_domain: string;
  reputation_tier: string;
  dampening_factor: number;
  age_days?: number | null;
  registrar?: string | null;
}

export interface NetworkDetails {
  dns_resolved?: boolean | null;
  dns_ttl?: number | null;
  dns_flags: string[];
  ssl_valid?: boolean | null;
  ssl_issuer?: string | null;
  ssl_days_until_expiry?: number | null;
  ssl_is_new_cert?: boolean | null;
  http_status?: number | null;
  redirect_count: number;
  final_url?: string | null;
  content_flags: string[];
}

export interface ScanDetails {
  ml?: MLDetails | null;
  domain?: DomainDetails | null;
  network?: NetworkDetails | null;
  risk_factors: string[];
  analysis_time_ms?: number | null;
}

export interface ScanResult {
  status: 'safe' | 'danger' | 'suspicious';
  message: string;
  risk_score: number;
  details?: ScanDetails | null;
}

// ── API Call ─────────────────────────────────────────────────

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
    console.error('Scan API Error:', error);
    return {
      status: 'suspicious',
      message: 'Could not connect to security server. Check your network.',
      risk_score: 0,
    };
  }
};
