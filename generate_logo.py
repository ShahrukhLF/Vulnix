from PIL import Image, ImageDraw

def create_vulnix_logo():
    # Create a 200x200 transparent image
    img = Image.new('RGBA', (200, 200), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)

    # Draw Left Wing of the 'V' (Darker Blue)
    draw.polygon([(20, 20), (80, 20), (100, 160), (40, 160)], fill="#1565C0")

    # Draw Right Wing of the 'V' (Standard Blue)
    draw.polygon([(180, 20), (120, 20), (100, 160), (160, 160)], fill="#1E88E5")

    # Draw Center Cyber/Shield Accent (Cyan)
    draw.polygon([(80, 20), (120, 20), (100, 70)], fill="#00E5FF")

    # Save to the local directory
    img.save('vulnix_logo.png')
    print("[+] Success! 'vulnix_logo.png' has been generated in your folder.")

if __name__ == "__main__":
    create_vulnix_logo()
