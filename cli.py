import click
from stego import crypto, embedder, extractor

@click.group()
def cli():
    """ steganography + AES CLI."""
    pass

@cli.command()
@click.option("--image", "image_path", required=True, type=click.Path(exists=True))
@click.option("--out", "output_path", required=True, type=click.Path())
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--message", prompt=True)
def hide(image_path, output_path, password, message):
    """Encrypt and hide MESSAGE inside IMAGE, saving to OUT."""
    aes = crypto.AESCipher(password)
    ciphertext = aes.encrypt(message.encode())
    embedder.embed_message_into_image(image_path, ciphertext, output_path)
    click.echo(f"Hidden message written to {output_path}")

@cli.command()
@click.option("--image", "image_path", required=True, type=click.Path(exists=True))
@click.option("--password", prompt=True, hide_input=True)
def extract(image_path, password):
    """Extract and decrypt hidden message from IMAGE."""
    ciphertext = extractor.extract_message_from_image(image_path)
    aes = crypto.AESCipher(password)
    plaintext = aes.decrypt(ciphertext)
    click.echo(f"Message:\n{plaintext.decode(errors='replace')}")

if __name__ == "__main__":
    cli()
