import click
from stego import crypto, embedder, extractor


@click.group()
def cli():
    """🔐 Hide & Seek – Securely hide encrypted messages inside images."""
    pass


@cli.command("hide")
@click.option("--image", "image_path", required=True, type=click.Path(exists=True),
              help="Path to the input image (PNG or BMP recommended).")
@click.option("--out", "output_path", required=True, type=click.Path(),
              help="Path where the output (stego) image will be saved.")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True,
              help="Password to encrypt the message.")
@click.option("--message", prompt=True,
              help="The secret message you want to hide.")
def hide_command(image_path, output_path, password, message):
    """Encrypt and embed a secret message into an image."""
    try:
        aes = crypto.AESCipher(password)
        ciphertext = aes.encrypt(message.encode("utf-8"))
        embedder.embed_message_into_image(image_path, ciphertext, output_path)
        click.secho(f"✅ Successfully embedded message into {output_path}", fg="green")
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")


@cli.command("extract")
@click.option("--image", "image_path", required=True, type=click.Path(exists=True),
              help="Path to the stego image containing the hidden message.")
@click.option("--password", prompt=True, hide_input=True,
              help="Password to decrypt the message.")
def extract_command(image_path, password):
    """Extract and decrypt a hidden message from an image."""
    try:
        ciphertext = extractor.extract_message_from_image(image_path)
        aes = crypto.AESCipher(password)
        plaintext = aes.decrypt(ciphertext)
        click.secho("🔓 Decrypted message:\n", fg="cyan")
        click.echo(plaintext.decode("utf-8", errors="replace"))
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")


if __name__ == "__main__":
    cli()
