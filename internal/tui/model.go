package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type View int

const (
	ViewSyscalls View = iota
	ViewLatency
	ViewEvents
)

type SyscallCount struct {
	Name  string
	Count uint64
}

type LatencyBucket struct {
	RangeLabel string
	Count      uint64
}

type EventLine struct {
	Timestamp time.Time
	Label     string
	Detail    string
}

type tickMsg time.Time
type syscallDataMsg []SyscallCount
type latencyDataMsg []LatencyBucket
type eventDataMsg EventLine

func NewSyscallDataMsg(rows []SyscallCount) tea.Msg  { return syscallDataMsg(rows) }
func NewLatencyDataMsg(rows []LatencyBucket) tea.Msg { return latencyDataMsg(rows) }
func NewEventDataMsg(e EventLine) tea.Msg            { return eventDataMsg(e) }

type Model struct {
	active   View
	pid      uint32
	syscalls []SyscallCount
	buckets  []LatencyBucket
	events   []EventLine
	width    int
	height   int
}

func NewModel(pid uint32) Model {
	return Model{active: ViewSyscalls, pid: pid}
}

func tickEvery() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tickEvery()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1":
			m.active = ViewSyscalls
		case "2":
			m.active = ViewLatency
		case "3":
			m.active = ViewEvents
		case "tab":
			m.active = (m.active + 1) % 3
		}
		return m, nil

	case syscallDataMsg:
		m.syscalls = msg
		return m, nil

	case latencyDataMsg:
		m.buckets = msg
		return m, nil

	case eventDataMsg:
		m.events = append(m.events, EventLine(msg))
		if len(m.events) > 200 {
			m.events = m.events[len(m.events)-200:]
		}
		return m, nil

	case tickMsg:
		return m, tickEvery()
	}
	return m, nil
}

func (m Model) View() string {
	header := renderHeader(m.pid, m.active)
	var body string
	switch m.active {
	case ViewSyscalls:
		body = renderSyscalls(m.syscalls)
	case ViewLatency:
		body = renderLatency(m.buckets)
	case ViewEvents:
		body = renderEvents(m.events)
	}
	footer := "[1] syscalls  [2] latency  [3] events  [tab] switch  [q] quit"
	return header + "\n" + body + "\n" + footer
}