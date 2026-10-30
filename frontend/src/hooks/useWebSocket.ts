import { useEffect, useRef, useState } from 'react'

export interface WsEvent {
  id: string
  ts: string
  type: 'alert' | 'incident' | 'info' | 'critical' | 'success'
  message: string
  org?: string
}

export function useWebSocket() {
  const [events, setEvents] = useState<WsEvent[]>([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()

  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${protocol}://${location.host}/ws/events`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => {
      setConnected(false)
      reconnectTimer.current = setTimeout(connect, 3000)
    }
    ws.onerror = () => ws.close()
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as WsEvent
        setEvents(prev => [data, ...prev].slice(0, 100))
      } catch {
        /* ignore */
      }
    }

    // Keep-alive ping every 25 s
    const ping = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping')
    }, 25_000)

    ws.onclose = () => {
      setConnected(false)
      clearInterval(ping)
      reconnectTimer.current = setTimeout(connect, 3000)
    }
  }

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [])

  return { events, connected }
}
