# Credentials

| Username | Password/Hash | Source | Notes |
|----------|--------------|--------|-------|
| activemq system | manager | /opt/activemq/conf/credentials.properties | ActiveMQ broker user |
| activemq guest | password | /opt/activemq/conf/credentials.properties | |
| jetty admin | admin | /opt/activemq/conf/jetty-realm.properties | Web console |
| jetty user | user | /opt/activemq/conf/jetty-realm.properties | |
| activemq admin | admin | /opt/activemq/conf/users.properties | ActiveMQ auth |
| activemq.password (enc) | ENC(mYRkg+4Q4hua1kvpCCI2hg==) | credentials-enc.properties | AES encrypted |
| guest.password (enc) | ENC(Cf3Jf3tM+UrSOoaKU50od5CuBa8rxjoL) | credentials-enc.properties | AES encrypted |

## Active Directory Credentials
| Username | Password/Hash | Source | Notes |
|----------|--------------|--------|-------|
| svc_laps@KING.HTB | 16bmxkingm@ | Kerberoast crack (john, rockyou) | RC4 TGS hash cracked |
| svc_sql@KING.HTB | r%msnCet4EA5#J | Kerberoast crack (same as SQL$ LAPS password) | RC4 TGS hash cracked |
| SQL$ (local admin on sql.king.htb) | r%msnCet4EA5#J | LAPS ms-Mcs-AdmPwd via svc_laps LDAP | SQL machine offline |

## Kerberos Ticket Files
| File | Principal | Notes |
|------|-----------|-------|
| /tmp/krb5cc_1600801117_Qxs0zd | svc_mq@KING.HTB | On mq target; exfiltrated as base64 this session |
| /home/takashi/.../svc_sql.ccache | svc_sql@KING.HTB | Generated via impacket-getTGT this session |

## SSH attempts (failed)
- anne : manager, admin, password, user → all failed
