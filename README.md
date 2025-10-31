# z25
z25

NOTES
102825:
*   eliminate double-sending block updates, maybe even throttle to 0.5s b/c console is screaming
*   gui driven "reports" function:
        how long are my data arrays?
        do they change in size or static (have a setting for length to keep, then set max of Display Minutes)
        messages received count, last tstamp
*   don't send block_update for single ticker messages ... probably the #1 slower
*   unsubscribe_all
*   cancel_order
*   dropped wss socket
*   value to order widget
*   channels rollup
*   remove console msgs (another slower)
*   hotlist impl!!
*   fetch history, load settings


it's flickering b/c soo many BTC msgs, and duplicates!

NEED: on connection closed need to delete the queue ... they could be overflowing ... add to report.
Also, when z25d prints "connection closed" need to cleanup its queues ... should be deleted.
Somehow lookAtMePCT/VOL is passing all 
Check for holdings w/o sell order
restart cbx not working
just subscribe to one mundane coin + BTC to investigate how it's getting lookAtMePCT/VOL=True
