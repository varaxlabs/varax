package explore

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Enter     key.Binding
	Back      key.Binding
	Quit      key.Binding
	Filter    key.Binding
	Benchmark key.Binding
	Help      key.Binding
}

var keys = keyMap{
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc", "backspace"),
		key.WithHelp("esc", "back"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Filter: key.NewBinding(
		key.WithKeys("f"),
		key.WithHelp("f", "filter status"),
	),
	Benchmark: key.NewBinding(
		key.WithKeys("b"),
		key.WithHelp("b", "filter benchmark"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
}
