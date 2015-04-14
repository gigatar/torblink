#include <stdio.h>
#include <pcap.h>
#include <wiringPi.h>
#include <time.h>
#include <signal.h>

/* Global VARs because I'm lazy */
unsigned long packet_count = 0;     /* Total number of packets */
float byte_count = 0;               /* Total Byte Count */
time_t last_log;                    /* Time since last log */
int running = 1;                    /* For signal catch */

/* flash the led */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet){
    digitalWrite(0, HIGH);
    delay(2);
    digitalWrite(0, LOW);
    packet_count++;
    byte_count += header->len;
}


/* Log progress */
void log_progress(int startup){
    float converted_bytes;
    char size_type[3];
    FILE *f = fopen("/var/log/torblink.log","a");

    /* Convert Bytes */
    if(byte_count >= 1000000000){
        converted_bytes = byte_count / 1000000000;
        strncpy(size_type,"GB", 3);
    }
    else if(byte_count >= 1000000){
        converted_bytes = byte_count / 1000000;
        strncpy(size_type,"MB", 3);
    }
    else if(byte_count >= 1000) {
        converted_bytes = byte_count / 1000;
        strncpy(size_type,"KB", 3);
    }
    else{
        converted_bytes = byte_count;
        strncpy(size_type,"B", 2);
    }

    /* Get time for logging */
    time_t t = time(NULL);
    struct tm * p = localtime(&t);
    char tstamp[50];
    strftime(tstamp, 50, "%b %d %T", p);

    /* Log */
    if (startup == 1) /* Log Startup */
    {
        fprintf(f,"\n\n\n**************************************\n* Started capture at %s *\n**************************************\n", tstamp);
    }
    else if (startup == 2){ /* Log Shutdown */
        fprintf(f,"[%s]: %lu pkts / %.2f %s\n", tstamp, packet_count, converted_bytes, size_type);
        fprintf(f,"\n***************************************\n* Stopping capture at %s *\n***************************************\n", tstamp);
    }
    else { /* Standard Logging */
        fprintf(f,"[%s]: %lu pkts / %.2f %s\n", tstamp, packet_count, converted_bytes, size_type);
        time(&last_log);
    }
    fclose(f);
}

/* signal Handler */
void sig_handler(int signum){
    /* Flush log and exit on SIGTERM */
    if(signum == SIGTERM){
        log_progress(2);
        running = 0;
    }

    // Flush log on USR1
    if(signum == SIGUSR1)
    {
        log_progress(0);       
    }
}

int main(int argc, char *argv[]){
    /* Setup Signal Handler */
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_handler);

    char *dev = "wlan0";                            /* device to sniff on*/
    char errbuf[PCAP_ERRBUF_SIZE];                  /* create our pcap error buffer */
    pcap_t *handle;                                 /* pcap handler */
    struct bpf_program fp;                          /* The compiled filter */
    char filter_exp[] = "port 9001 or port 9030";   /* The filter expression */
    bpf_u_int32 mask;                               /* Our netmask */
    bpf_u_int32 net;                                /* Our IP */


    /* Ensure that we can get our IP and Netmask */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    /* Create the handler to the capture */
    handle = pcap_open_live(dev, BUFSIZ, 0, 20, errbuf);

    /* Check if handler creation was successful */
    if(handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s", dev, errbuf);
        return 2;
    }

    /* Ensure we're using Ethernet headers */
    if (pcap_datalink(handle) != DLT_EN10MB) { 
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return 3;
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 4;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 5;
    }

    /* Setup wiringPi */
    wiringPiSetup();
    pinMode (0, OUTPUT);

    /* setup logging */
    time_t cur_run;
    double diff_t;
    time(&last_log);

    log_progress(1);
    /* Start our capture         *
     * got_packet will be called *
     * everytime we get a packet *
     * that matches our filter   */
    while(running){
        pcap_loop(handle, 1, got_packet, NULL);
        time(&cur_run);
        diff_t = difftime(cur_run, last_log);

        if(diff_t >= (60 * 30))
            log_progress(0);
    }


    /* turn off LED before exit */
    digitalWrite(0, LOW);

    /* close the session */
    pcap_close(handle);
    return 0;
}
