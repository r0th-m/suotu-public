import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'

// 三类日志子页(与后端 logging_setup.LOG_FILES 对齐)
const LOG_SUBS = [
  { key: 'app', label: '运行' },
  { key: 'error', label: '错误' },
  { key: 'operation', label: '操作' },
]
const TAIL_OPTIONS = [100, 200, 500]
const AUTO_MS = 5000

// 行格式(logging_setup.SensitiveFormatter):
//   2026-08-06 23:53:53,078 INFO suotu.app main: 消息
// 不匹配的行视为上一条的延续(error.log 堆栈行),随上一条级别着色
const LINE_RE = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) ([A-Z]+) ([\w.]+) ([\w<>]+): (.*)$/

function levelClass(level) {
  if (level === 'ERROR' || level === 'CRITICAL') return 'log-lvl-error'
  if (level === 'WARNING' || level === 'WARN') return 'log-lvl-warn'
  return ''
}

function fmtSize(n) {
  if (n == null) return '-'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

function fmtTime(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('zh-CN', { hour12: false })
}

/**
 * 运行日志查看器(移植自主机取证平台 v1.2.0,排障用,系统级与案件无关):
 * 三子页(运行/错误/操作)+ 关键字过滤(服务端,先取尾部再过滤)+ 尾部行数 +
 * 手动/自动(5s)刷新;error 堆栈延续行随上一条级别着色、pre-wrap 展示;
 * 「下载诊断包」POST /diagnostics/bundle(生成动作后端写审计链)。
 * 挂在 App 顶栏「运行日志」弹窗内;提示条组件内自管(索图无全局 toast)。
 */
export default function LogViewer() {
  const [sub, setSub] = useState('app')
  const [tail, setTail] = useState(200)
  const [q, setQ] = useState('')
  const [qInput, setQInput] = useState('')
  const [data, setData] = useState(null) // { file, requested, matched, lines }
  const [files, setFiles] = useState(null) // /logs/files
  const [auto, setAuto] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [diagBusy, setDiagBusy] = useState(false)
  const bodyRef = useRef(null)

  const load = useCallback(() => {
    api.readLog(sub, { lines: tail, q: q || undefined })
      .then((d) => { setData(d); setError(null) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [sub, tail, q])

  const loadFiles = useCallback(() => {
    api.listLogFiles().then((d) => setFiles(d.files)).catch(() => setFiles(null))
  }, [])

  useEffect(() => { setLoading(true); load() }, [load])
  useEffect(() => { loadFiles() }, [loadFiles])

  // 自动刷新(5s):日志尾部 + 文件信息一起刷;开关关闭/组件卸载即停
  useEffect(() => {
    if (!auto) return undefined
    const t = setInterval(() => { load(); loadFiles() }, AUTO_MS)
    return () => clearInterval(t)
  }, [auto, load, loadFiles])

  // 新数据落底(日志看尾部,最新在最后)
  useEffect(() => {
    const el = bodyRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [data])

  const refresh = () => { setLoading(true); load(); loadFiles() }

  const downloadBundle = async () => {
    setDiagBusy(true)
    setNotice(null)
    try {
      const { blob, filename } = await api.downloadDiagnostics()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      setNotice('诊断包已下载(生成动作已写审计链)')
    } catch (e) {
      setNotice(`诊断包下载失败: ${e.message}`)
    } finally {
      setDiagBusy(false)
    }
  }

  // 逐行解析:命中行格式 → 结构化渲染;否则为上一条延续(堆栈),随上条级别
  let prevLevel = ''
  const rows = (data?.lines || []).map((text, i) => {
    const m = LINE_RE.exec(text)
    if (!m) {
      return { key: i, cont: true, text, lvl: prevLevel }
    }
    const [, ts, level, logger, module, msg] = m
    prevLevel = levelClass(level)
    return { key: i, cont: false, ts, level, logger, module, msg, lvl: prevLevel }
  })

  return (
    <div className="log-pane">
      <div className="sub-tabs">
        {LOG_SUBS.map((s) => (
          <button
            key={s.key}
            className={sub === s.key ? 'tab active' : 'tab'}
            onClick={() => setSub(s.key)}
          >
            {s.label} <span className="muted">{s.key}.log</span>
          </button>
        ))}
      </div>
      <div className="log-files mono muted">
        {(files || []).map((f) => (
          <span key={f.file} className="log-file-item">
            {f.name}: {f.exists ? `${fmtSize(f.size)} · 更新 ${fmtTime(f.mtime)}` : '尚未生成'}
          </span>
        ))}
        {!files && <span>文件信息加载中…</span>}
        <span className="log-files-note">日志目录 data/logs/(10MB×5 轮转,与审计链严格分离)</span>
      </div>
      <div className="log-toolbar">
        <input
          placeholder="关键字过滤(先取尾部再过滤),回车生效"
          value={qInput}
          onChange={(e) => setQInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') setQ(qInput.trim()) }}
        />
        {q && <button className="link-btn" onClick={() => { setQ(''); setQInput('') }}>清除过滤</button>}
        <select value={tail} onChange={(e) => setTail(Number(e.target.value))}>
          {TAIL_OPTIONS.map((n) => <option key={n} value={n}>尾部 {n} 行</option>)}
        </select>
        <button onClick={refresh}>刷新</button>
        <label className="checkbox-label">
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
          自动刷新(5s)
        </label>
        <span className="log-toolbar-gap" />
        <button
          disabled={diagBusy}
          title="报障用:含三个日志尾部 + 版本 + 脱敏配置 + 错误统计 + 审计链状态;key/口令一律打码,不含值"
          onClick={downloadBundle}
        >
          {diagBusy ? '打包中…' : '下载诊断包'}
        </button>
      </div>
      <div className="log-meta mono muted">
        {data
          ? `${data.file}.log · 尾部 ${data.requested} 行${q ? ` · 匹配 ${data.matched} 行(关键字「${q}」)` : ` · 返回 ${data.matched} 行`}${auto ? ' · 自动刷新中' : ''}`
          : '加载中…'}
      </div>
      {notice && <div className="banner banner-warn" onClick={() => setNotice(null)} title="点击关闭">{notice}</div>}
      {error && <div className="banner banner-error">{error}</div>}
      <div className="log-lines mono" ref={bodyRef}>
        {rows.map((r) => r.cont ? (
          <div key={r.key} className={`log-line log-cont ${r.lvl}`}>{r.text}</div>
        ) : (
          <div key={r.key} className={`log-line ${r.lvl}`}>
            <span className="log-ts">{r.ts}</span>
            {' '}
            <span className={`log-level ${r.lvl}`}>{r.level}</span>
            {' '}
            <span className="log-mod">{r.logger} {r.module}</span>
            <span className="log-msg">: {r.msg}</span>
          </div>
        ))}
        {data && rows.length === 0 && <div className="muted log-empty">无日志行</div>}
        {loading && <div className="muted log-empty">加载中…</div>}
      </div>
    </div>
  )
}
