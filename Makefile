firewall: main.py
		python3 ./$< >$@ 
		chmod +x $@ 
		cp main.py firewall
		dos2unix firewall