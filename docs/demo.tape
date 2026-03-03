Output docs/demo.gif
Set Shell "bash"
Set Width 1100
Set Height 750
Set FontSize 18
Set Theme "Dracula"
Set Padding 30
Set Framerate 24
Set TypingSpeed 50ms

# Show the demo scan
Type "vxpwngard demo"
Sleep 1s
Enter
Sleep 8s

# Quick pause at the end so they see the summary
Sleep 3s

# Now show scanning a clean repo
Type "vxpwngard scan ."
Sleep 1s
Enter
Sleep 4s
