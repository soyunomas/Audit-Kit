package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	// 1. Create application
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())

	w := a.NewWindow("🐚 Reverse Shell Generator")
	w.Resize(fyne.NewSize(1100, 800)) // Ventana un poco más grande

	// --- State Variables ---
	currentOS := "Linux"
	currentPayload := ""
	isDarkMode := true
	
	// --- Input Widgets ---
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("192.168.2.100")
	ipEntry.SetText("192.168.2.100")

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("2525")
	portEntry.SetText("2525")

	// --- Output Widgets ---
	listenerOutput := widget.NewMultiLineEntry()
	listenerOutput.TextStyle = fyne.TextStyle{Monospace: true}
	listenerOutput.SetMinRowsVisible(3)

	payloadOutput := widget.NewMultiLineEntry()
	payloadOutput.TextStyle = fyne.TextStyle{Monospace: true}
	payloadOutput.SetMinRowsVisible(8)
	payloadOutput.Wrapping = fyne.TextWrapWord

	// --- NUEVO WIDGET DE AYUDA (MEJORADO) ---
	// Usamos RichTextFromMarkdown para máximo contraste y estilo
	helpOutput := widget.NewRichTextFromMarkdown("")
	helpOutput.Wrapping = fyne.TextWrapWord
	// Envolvemos el texto en un scroll para asegurar que tenga altura fija y sea navegable
	helpScroll := container.NewVScroll(helpOutput)
	helpScroll.SetMinSize(fyne.NewSize(0, 200)) // Forzamos altura mínima de 200px

	statusLabel := widget.NewLabel("Ready")
	statusLabel.Alignment = fyne.TextAlignCenter

	// --- Logic Functions ---

	getKeys := func(m map[string]string) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}

	generate := func(encodingType string) {
		ip := ipEntry.Text
		port := portEntry.Text
		if ip == "" { ip = "192.168.2.100" }
		if port == "" { port = "2525" }

		// 1. Generate Listener
		listenerCmd := "nc -lvnp " + port
		if currentOS == "Windows" {
			listenerCmd = "nc.exe -lvnp " + port
		}
		listenerOutput.SetText(listenerCmd)

		// 2. Generate Payload
		var rawPayload string
		var ok bool

		if currentOS == "Linux" {
			rawPayload, ok = LinuxPayloads[currentPayload]
		} else {
			rawPayload, ok = WindowsPayloads[currentPayload]
		}

		if !ok || rawPayload == "" {
			payloadOutput.SetText("")
			helpOutput.ParseMarkdown("_Selecciona un payload para ver información detallada._")
			return
		}

		// 3. BUSCAR Y MOSTRAR AYUDA (METADATA)
		// Usamos formato Markdown para negritas y mejor lectura
		meta, metaOk := PayloadHelp[currentPayload]
		if metaOk {
			mdText := fmt.Sprintf("### 📖 INFO\n%s\n\n### 🛡️ OPSEC\n%s\n\n### 💡 TIP\n%s", 
				meta.Description, meta.OpSec, meta.Consejo)
			helpOutput.ParseMarkdown(mdText)
		} else {
			helpOutput.ParseMarkdown("ℹ️ _No hay información adicional disponible para este payload._")
		}

		// Replace Placeholders
		res := strings.ReplaceAll(rawPayload, "{ip}", ip)
		res = strings.ReplaceAll(res, "{port}", port)

		// Encode
		switch encodingType {
		case "Base64":
			res = base64.StdEncoding.EncodeToString([]byte(res))
		case "URL":
			res = url.QueryEscape(res)
		case "Double URL":
			res = url.QueryEscape(url.QueryEscape(res))
		}

		payloadOutput.SetText(res)
		statusLabel.SetText("Generated: " + currentPayload + " (" + encodingType + ")")
	}

	// --- Controls ---
	encodingSelect := widget.NewSelect([]string{"None", "Base64", "URL", "Double URL"}, func(s string) {
		generate(s)
	})
	encodingSelect.SetSelected("None")

	payloadSelect := widget.NewSelect(getKeys(LinuxPayloads), func(s string) {
		currentPayload = s
		generate(encodingSelect.Selected)
	})

	osSelect := widget.NewSelect([]string{"Linux", "Windows"}, func(s string) {
		currentOS = s
		if s == "Linux" {
			payloadSelect.Options = getKeys(LinuxPayloads)
		} else {
			payloadSelect.Options = getKeys(WindowsPayloads)
		}
		if len(payloadSelect.Options) > 0 {
			payloadSelect.SetSelected(payloadSelect.Options[0])
		}
		payloadSelect.Refresh()
	})
	osSelect.SetSelected("Linux")

	ipEntry.OnChanged = func(s string) { generate(encodingSelect.Selected) }
	portEntry.OnChanged = func(s string) { generate(encodingSelect.Selected) }

	themeBtn := widget.NewButtonWithIcon("Light Mode", theme.ColorPaletteIcon(), nil)
	themeBtn.OnTapped = func() {
		if isDarkMode {
			a.Settings().SetTheme(theme.LightTheme())
			themeBtn.SetText("Dark Mode")
			isDarkMode = false
		} else {
			a.Settings().SetTheme(theme.DarkTheme())
			themeBtn.SetText("Light Mode")
			isDarkMode = true
		}
	}

	copyListenerBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		w.Clipboard().SetContent(listenerOutput.Text)
		statusLabel.SetText("✅ Listener Copied!")
	})

	copyPayloadBtn := widget.NewButtonWithIcon("Copy Payload", theme.ContentCopyIcon(), func() {
		w.Clipboard().SetContent(payloadOutput.Text)
		statusLabel.SetText("✅ Payload Copied!")
	})

	// --- Layout Construction ---

	configForm := widget.NewForm(
		widget.NewFormItem("IP Address (LHOST)", ipEntry),
		widget.NewFormItem("Port (LPORT)", portEntry),
		widget.NewFormItem("Operating System", osSelect),
		widget.NewFormItem("Payload Type", payloadSelect),
		widget.NewFormItem("Encoding", encodingSelect),
	)

	// Usamos un Card para que el área de ayuda tenga un borde y fondo sutil
	helpCard := widget.NewCard("Payload Details", "", helpScroll)

	// Panel Izquierdo
	leftPanel := container.NewBorder(
		container.NewBorder(nil, nil, 
			widget.NewLabelWithStyle("🔌 Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			themeBtn,
		), 
		helpCard, // Ponemos la tarjeta de ayuda abajo del todo
		nil, nil,
		container.NewVBox(configForm), // Centro: Formulario
	)

	rightPanel := container.NewBorder(
		nil, nil, nil, nil,
		container.NewVBox(
			widget.NewLabelWithStyle("👂 Listener", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, copyListenerBtn, listenerOutput),
			
			layout.NewSpacer(),
			
			widget.NewLabelWithStyle("⚡ Payload", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, copyPayloadBtn, nil, nil, payloadOutput),
		),
	)

	split := container.NewHSplit(
		container.NewPadded(leftPanel),
		container.NewPadded(rightPanel),
	)
	split.SetOffset(0.4)

	footer := container.NewHBox(
		layout.NewSpacer(),
		statusLabel,
		layout.NewSpacer(),
		widget.NewLabel("Mit License"),
	)

	content := container.NewBorder(nil, footer, nil, nil, split)

	w.SetContent(content)
	
	if len(payloadSelect.Options) > 0 {
		payloadSelect.SetSelected(payloadSelect.Options[0])
	}

	w.ShowAndRun()
}
