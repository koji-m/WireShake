all:
	cargo build --release

install:
	install -Dm 755 target/release/wire_shake /usr/bin/wire_shake
	mkdir -p /usr/share/wire_shake/ui
	install -Dm 755 ui/* /usr/share/wire_shake/ui/
	install -Dm 644 assets/wire_shake.desktop /usr/share/applications/wire_shake.desktop
	install -Dm 644 assets/icon_48x48.png /usr/share/icons/hicolor/48x48/apps/wire_shake.png
	install -Dm 644 assets/icon_64x64.png /usr/share/icons/hicolor/64x64/apps/wire_shake.png
	install -Dm 644 assets/icon_128x128.png /usr/share/icons/hicolor/128x128/apps/wire_shake.png
	gtk-update-icon-cache /usr/share/icons/hicolor

uninstall:
	rm /usr/bin/wire_shake
	rm -r /usr/share/wire_shake
	rm /usr/share/applications/wire_shake.desktop
	rm /usr/share/icons/hicolor/48x48/apps/wire_shake.png
	rm /usr/share/icons/hicolor/64x64/apps/wire_shake.png
	rm /usr/share/icons/hicolor/128x128/apps/wire_shake.png
	gtk-update-icon-cache /usr/share/icons/hicolor


