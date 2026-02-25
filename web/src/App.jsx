import { useEffect, useMemo, useState } from 'react'
import { apiRequest, getToken, login, logout } from './api'

const TABS = [
  { id: 'upstreams', label: '上游订阅' },
  { id: 'nodes', label: '手动节点' },
  { id: 'settings', label: '系统设置' },
  { id: 'backup', label: '备份恢复' }
]

const emptyUpstream = {
  name: '',
  url: '',
  enabled: true,
  refresh_interval: 60
}

const emptyNode = {
  name: '',
  raw_uri: '',
  enabled: true,
  group_name: 'default'
}

function App() {
  const [booting, setBooting] = useState(true)
  const [authed, setAuthed] = useState(false)
  const [admin, setAdmin] = useState(null)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('upstreams')

  const [upstreams, setUpstreams] = useState([])
  const [nodes, setNodes] = useState([])
  const [settings, setSettings] = useState(null)

  const [upstreamForm, setUpstreamForm] = useState(emptyUpstream)
  const [nodeForm, setNodeForm] = useState(emptyNode)

  const [loginForm, setLoginForm] = useState({ username: 'admin', password: 'admin123' })
  const [passwordForm, setPasswordForm] = useState({ old_password: '', new_password: '' })
  const [backupJSON, setBackupJSON] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const boot = async () => {
      if (!getToken()) {
        setBooting(false)
        return
      }
      try {
        await fetchMe()
        setAuthed(true)
      } catch {
        setAuthed(false)
      } finally {
        setBooting(false)
      }
    }
    boot()
  }, [])

  const statusSummary = useMemo(() => {
    return {
      upstreamEnabled: upstreams.filter((item) => item.enabled).length,
      nodeEnabled: nodes.filter((item) => item.enabled).length
    }
  }, [upstreams, nodes])

  async function fetchMe() {
    const me = await apiRequest('/api/me')
    setAdmin(me)
    return me
  }

  async function fetchAll() {
    const [upstreamData, nodeData, settingsData] = await Promise.all([
      apiRequest('/api/upstreams'),
      apiRequest('/api/nodes'),
      apiRequest('/api/settings')
    ])
    setUpstreams(upstreamData)
    setNodes(nodeData)
    setSettings(settingsData)
  }

  async function handleLogin(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(loginForm.username, loginForm.password)
      await fetchMe()
      await fetchAll()
      setAuthed(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function handleLogout() {
    setBusy(true)
    try {
      await logout()
      setAuthed(false)
      setAdmin(null)
      setUpstreams([])
      setNodes([])
      setSettings(null)
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (!authed) return
    fetchAll().catch((err) => setError(err.message))
  }, [authed])

  async function createUpstream(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/upstreams', {
        method: 'POST',
        body: JSON.stringify(upstreamForm)
      })
      setUpstreamForm(emptyUpstream)
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function updateUpstream(item) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/upstreams/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify(item)
      })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function deleteUpstream(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/upstreams/${id}`, { method: 'DELETE' })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function syncUpstream(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/upstreams/${id}/sync`, { method: 'POST' })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function syncAll() {
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/sync', { method: 'POST' })
      setUpstreams(await apiRequest('/api/upstreams'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function createNode(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/nodes', {
        method: 'POST',
        body: JSON.stringify(nodeForm)
      })
      setNodeForm(emptyNode)
      setNodes(await apiRequest('/api/nodes'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function updateNode(item) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/nodes/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify(item)
      })
      setNodes(await apiRequest('/api/nodes'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function deleteNode(id) {
    setBusy(true)
    setError('')
    try {
      await apiRequest(`/api/nodes/${id}`, { method: 'DELETE' })
      setNodes(await apiRequest('/api/nodes'))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function saveSettings(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const payload = {
        cache_mode: settings.cache_mode,
        cache_interval: Number(settings.cache_interval),
        output_template: settings.output_template
      }
      const data = await apiRequest('/api/settings', {
        method: 'PUT',
        body: JSON.stringify(payload)
      })
      setSettings(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function changePassword(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await apiRequest('/api/password', {
        method: 'PUT',
        body: JSON.stringify(passwordForm)
      })
      setPasswordForm({ old_password: '', new_password: '' })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function exportBackup() {
    setBusy(true)
    setError('')
    try {
      const payload = await apiRequest('/api/backup/export')
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `subadmin-backup-${Date.now()}.json`
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function importBackup(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const parsed = JSON.parse(backupJSON)
      await apiRequest('/api/backup/import', {
        method: 'POST',
        body: JSON.stringify(parsed)
      })
      await fetchAll()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (booting) {
    return <div className="center">初始化中...</div>
  }

  if (!authed) {
    return (
      <main className="auth-wrap">
        <section className="auth-card">
          <h1>SubAdmin</h1>
          <p>个人订阅管理中心</p>
          <form onSubmit={handleLogin}>
            <label>
              用户名
              <input
                value={loginForm.username}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, username: e.target.value }))}
                required
              />
            </label>
            <label>
              密码
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, password: e.target.value }))}
                required
              />
            </label>
            <button disabled={busy} type="submit">
              登录
            </button>
          </form>
          {error && <div className="error-box">{error}</div>}
        </section>
      </main>
    )
  }

  return (
    <main className="layout">
      <header className="topbar">
        <div>
          <h1>SubAdmin 控制台</h1>
          <p>
            管理员：{admin?.username || 'unknown'} | 已启用上游 {statusSummary.upstreamEnabled} 个，手动节点{' '}
            {statusSummary.nodeEnabled} 个
          </p>
        </div>
        <div className="actions">
          <button onClick={syncAll} disabled={busy}>
            全量同步
          </button>
          <button onClick={handleLogout} disabled={busy} className="ghost">
            退出
          </button>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={tab.id === activeTab ? 'active' : ''}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {error && <div className="error-box">{error}</div>}

      {activeTab === 'upstreams' && (
        <section className="panel">
          <h2>上游订阅管理</h2>
          <form className="grid-form" onSubmit={createUpstream}>
            <input
              placeholder="名称"
              value={upstreamForm.name}
              onChange={(e) => setUpstreamForm((prev) => ({ ...prev, name: e.target.value }))}
            />
            <input
              placeholder="订阅 URL"
              value={upstreamForm.url}
              onChange={(e) => setUpstreamForm((prev) => ({ ...prev, url: e.target.value }))}
            />
            <input
              type="number"
              min="1"
              placeholder="同步间隔(分钟)"
              value={upstreamForm.refresh_interval}
              onChange={(e) =>
                setUpstreamForm((prev) => ({ ...prev, refresh_interval: Number(e.target.value) || 60 }))
              }
            />
            <label className="inline-check">
              <input
                type="checkbox"
                checked={upstreamForm.enabled}
                onChange={(e) => setUpstreamForm((prev) => ({ ...prev, enabled: e.target.checked }))}
              />
              启用
            </label>
            <button disabled={busy}>新增上游</button>
          </form>

          <div className="list-wrap">
            {upstreams.map((item) => (
              <article className="list-row" key={item.id}>
                <input
                  value={item.name}
                  onChange={(e) =>
                    setUpstreams((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, name: e.target.value } : u))
                    )
                  }
                />
                <input
                  value={item.url}
                  onChange={(e) =>
                    setUpstreams((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, url: e.target.value } : u))
                    )
                  }
                />
                <input
                  type="number"
                  value={item.refresh_interval}
                  onChange={(e) =>
                    setUpstreams((prev) =>
                      prev.map((u) =>
                        u.id === item.id ? { ...u, refresh_interval: Number(e.target.value) || 60 } : u
                      )
                    )
                  }
                />
                <label className="inline-check">
                  <input
                    type="checkbox"
                    checked={item.enabled}
                    onChange={(e) =>
                      setUpstreams((prev) =>
                        prev.map((u) => (u.id === item.id ? { ...u, enabled: e.target.checked } : u))
                      )
                    }
                  />
                  启用
                </label>
                <small>{item.last_status || '未同步'}</small>
                <div className="row-actions">
                  <button onClick={() => syncUpstream(item.id)} disabled={busy}>
                    同步
                  </button>
                  <button onClick={() => updateUpstream(item)} disabled={busy}>
                    保存
                  </button>
                  <button onClick={() => deleteUpstream(item.id)} disabled={busy} className="danger">
                    删除
                  </button>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'nodes' && (
        <section className="panel">
          <h2>手动节点管理</h2>
          <form className="grid-form" onSubmit={createNode}>
            <input
              placeholder="名称"
              value={nodeForm.name}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, name: e.target.value }))}
            />
            <input
              placeholder="节点 URI"
              value={nodeForm.raw_uri}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, raw_uri: e.target.value }))}
            />
            <input
              placeholder="分组"
              value={nodeForm.group_name}
              onChange={(e) => setNodeForm((prev) => ({ ...prev, group_name: e.target.value }))}
            />
            <label className="inline-check">
              <input
                type="checkbox"
                checked={nodeForm.enabled}
                onChange={(e) => setNodeForm((prev) => ({ ...prev, enabled: e.target.checked }))}
              />
              启用
            </label>
            <button disabled={busy}>新增节点</button>
          </form>

          <div className="list-wrap">
            {nodes.map((item) => (
              <article className="list-row" key={item.id}>
                <input
                  value={item.name}
                  onChange={(e) =>
                    setNodes((prev) => prev.map((u) => (u.id === item.id ? { ...u, name: e.target.value } : u)))
                  }
                />
                <input
                  value={item.raw_uri}
                  onChange={(e) =>
                    setNodes((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, raw_uri: e.target.value } : u))
                    )
                  }
                />
                <input
                  value={item.group_name}
                  onChange={(e) =>
                    setNodes((prev) =>
                      prev.map((u) => (u.id === item.id ? { ...u, group_name: e.target.value } : u))
                    )
                  }
                />
                <label className="inline-check">
                  <input
                    type="checkbox"
                    checked={item.enabled}
                    onChange={(e) =>
                      setNodes((prev) =>
                        prev.map((u) => (u.id === item.id ? { ...u, enabled: e.target.checked } : u))
                      )
                    }
                  />
                  启用
                </label>
                <div className="row-actions">
                  <button onClick={() => updateNode(item)} disabled={busy}>
                    保存
                  </button>
                  <button onClick={() => deleteNode(item.id)} disabled={busy} className="danger">
                    删除
                  </button>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'settings' && settings && (
        <section className="panel">
          <h2>系统设置</h2>
          <form className="settings" onSubmit={saveSettings}>
            <label className="inline-check">
              <input
                type="checkbox"
                checked={settings.cache_mode}
                onChange={(e) => setSettings((prev) => ({ ...prev, cache_mode: e.target.checked }))}
              />
              缓存模式（推荐）
            </label>
            <label>
              缓存刷新间隔（分钟）
              <input
                type="number"
                min="1"
                value={settings.cache_interval}
                onChange={(e) =>
                  setSettings((prev) => ({ ...prev, cache_interval: Number(e.target.value) || 10 }))
                }
              />
            </label>
            <label>
              输出模板
              <input
                value={settings.output_template}
                onChange={(e) => setSettings((prev) => ({ ...prev, output_template: e.target.value }))}
              />
            </label>
            <button disabled={busy}>保存设置</button>
          </form>

          <h3>修改密码</h3>
          <form className="grid-form" onSubmit={changePassword}>
            <input
              type="password"
              placeholder="旧密码"
              value={passwordForm.old_password}
              onChange={(e) => setPasswordForm((prev) => ({ ...prev, old_password: e.target.value }))}
            />
            <input
              type="password"
              placeholder="新密码（至少6位）"
              value={passwordForm.new_password}
              onChange={(e) => setPasswordForm((prev) => ({ ...prev, new_password: e.target.value }))}
            />
            <button disabled={busy}>更新密码</button>
          </form>
        </section>
      )}

      {activeTab === 'backup' && (
        <section className="panel">
          <h2>备份恢复</h2>
          <div className="row-actions">
            <button disabled={busy} onClick={exportBackup}>
              导出 JSON 备份
            </button>
          </div>
          <form onSubmit={importBackup}>
            <label>
              粘贴备份 JSON 后恢复
              <textarea
                rows="14"
                value={backupJSON}
                onChange={(e) => setBackupJSON(e.target.value)}
                placeholder={`{\n  "admins": [...], ...\n}`}
              />
            </label>
            <button disabled={busy}>导入恢复</button>
          </form>
        </section>
      )}
    </main>
  )
}

export default App
