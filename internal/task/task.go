package task

import "shixi-proj/internal/store"

// 占位：后续可扩展为任务表 + 状态机 + 任务去重等
type Manager struct {
	st *store.Store
}

func NewManager(st *store.Store) *Manager { return &Manager{st: st} }

func (m *Manager) DebugList() []string {
	return []string{"(skeleton) tasks listing placeholder"}
}
