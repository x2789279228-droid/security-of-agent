export type ServiceId = 'vector' | 'window' | 'summary'
export type ServiceHealth = 'ok' | 'warn' | 'error'

export interface Service {
  id: ServiceId
  name: string
  description: string
  health: ServiceHealth
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface SecurityLog {
  id: number
  session_id: string
  event_type: string
  severity: Severity
  src_ip: string
  dst_ip: string
  message: string
  analyzed: boolean
  created_at: string
  is_anomaly?: boolean
  anomaly_score?: number
}
