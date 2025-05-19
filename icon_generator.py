from PIL import Image, ImageDraw

# Create a new image with a white background
size = (256, 256)
icon = Image.new('RGB', size, 'white')
draw = ImageDraw.Draw(icon)

# Draw a blue rounded rectangle for the device
device_color = '#2196F3'
draw.rounded_rectangle([(50, 50), (206, 206)], fill=device_color, radius=20)

# Draw white WiFi arcs
center = (128, 128)
arc_color = 'white'
for radius in [60, 45, 30]:
    bbox = (
        center[0] - radius,
        center[1] - radius,
        center[0] + radius,
        center[1] + radius
    )
    draw.arc(bbox, 45, 135, fill=arc_color, width=8)

# Save the icon
icon.save('assets/icon.ico', format='ICO', sizes=[(256, 256)])
icon.save('assets/icon.png', format='PNG') 