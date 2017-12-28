(use-modules (rnrs bytevectors))
(use-modules (system foreign))

(define (register-dissector tbl num dsctr)
  (set-dissector dissector-table tbl num dsctr))

(define (dissect-arp bv pinfo)
  (set-proto pinfo "ARP")
  (list
    (list
      "Address Resolution Protocol"
      (number->string (bytevector-u16-ref bv 6 (endianness big))))
    (list
      (list "Source Protocol Address"
            (inet-ntop AF_INET (bytevector-u32-ref bv 14 (endianness big))))
      '()
      (list
          (list "Destination Protocol Address"
                (inet-ntop AF_INET (bytevector-u32-ref bv 24 (endianness big)))) '() '()))
    '()))

(register-dissector 'net #x0806 dissect-arp)

