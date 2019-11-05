# mincg
Min. firmware version manager for Playstation Vita/TV

## Description
This toolset lets you manage PS Vita/TV's SMI data which stores the minfw ("factory firmware") version.
<br>How does it work? - Check out Moth Exploit by TeamMolecule/xyz: https://wiki.henkaku.xyz/vita/Vulnerabilities#moth_exploit </br>

### PC tool
This tool lets you find a compatible signed SMI block for your console.

### Vita tool
This tool lets you Flash/Dump the SMI data including per-console SMI decryption keys.

## Usage
	1) Download and install mincg.vpk on the console.
	2) Open mincg and press [CROSS] to dump the SMI data.
	3) Copy the _SMI_ files from ux0:data/ to your PC
		- Please consider sending the dump to skgleba@gmail.com to help out other users.
	4) Copy the [.SMI_KEY] file to the mincg/pctool/ directory
		- Rename it to something short, i.e "cur.key".
	5) Run the mincg pc tool with the key-file name as the argument
		- i.e "./mincg cur.key".
	6) If there is a match - congrats, you are lucky (there are only 3/256 chances)
		- If your own, previously contributed SMI got a match, you can remove or rename it from the /keys/ directory and re-run the tool.
	7) Copy the "TSMI.SMI" file from /mincg/ to ux0:data/ on Playstation Vita/TV
	8) Open mincg and press [CIRCLE] to flash the new SMI data.
		- If it fails, please send me "ux0:data/mincg.log" and your _SMI_ files
	9) Thats it! You just changed your minfw version.
	
## Notes
	- You do it at your own risk, i take no responsability for whatever happens to your console.
	- The PC tool requires OpenSSL (enc).
	- mincg creates a log in "ux0:data/mincg.log".
	- You should NOT downgrade below 3.60 if your min fw was higher than it, there may be some hardware differences on lower firmwares.
	- You should NOT update to 3.74+ when it gets released, sony may patch this exploit.
	
## Credits
	- Team Molecule / xyz for the Moth Exploit, update_sm 0x50002 exploit and help over discord
	- Team Molecule for HenKaku and TaiHen
	- xerpi for TaiHen plugin loader
	- All testers and everyone who contributed with their SMI dumps.
