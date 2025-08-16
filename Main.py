import EC_El_Gamal as eg
import XTEA_DH as xdh


#small prime and generator
#p=23
#g=5




#2048-bit MODP Group
# hexp='FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'
# p=int(hexp,16)
# print(p)

#calculated p ahead of time:
p=32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559



#Generator of MODP-2048
g=2


RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDER = "\033[4m"
MAGENTA = "\033[35m"


    

def publicAirwaves(Sender, msg, Recipient, s,r):
    file1 = open("publicLogs.txt","a")
    
    

    file1.write(msg)    
    
    
    file1.write("\n")

    

    file1.close()
    
    Recipient=op.getUser(Recipient)
    
    Recipient.addToInbox(Sender,msg , s, r)



def keyGen():
        
    
    gPriv=eg.privateKey()
    gPub=eg.publicKey(gPriv)

    #DH
    dhPriv,dhPub=xdh.generate_keys(p,g)
    
    
    
    return dhPriv,dhPub,gPriv,gPub
    


    
class Operator:

    def __init__(self):
        self.dhPriv,self.dhPub,self.gPriv,self.gPub=keyGen()
        self.name="Operator"
        self.users=[] #[i][0]=name [i][1]=DH key [i][2]=el gamal public key [i][3]=XTEA key [i][4]=user instance

    
    #returns user instance given a name
    def getUser(self,name):
        for u in self.users:
            if (u[0]==name):
                return u[4]
    #return it's own public DH key
    def getOPDH(self):
        return self.dhPub
    #return it's own public el gamal key
    def getOPGAMAL(self):
        return self.gPub
    
    #returns the DH key of a user's given name
    def getDH(self,name):
        
        for u in self.users:
            if (u[0]==name):
                return u[1]
    #returns the el gamal key of a user's given name
    def getGAMAL(self,name):
        for u in self.users:
            if (u[0]==name):
                return u[2]
            
    #create and return a user, giving the user the operator's public keys
    def createUser(self,name):
        newuser=User(name,self.dhPub,self.gPub,self)
        return newuser
    #called from within the user, the user provides their own generated public keys and their User instance.
    #the function adds the user to it's database
    def addUser(self, name,dhk,gk,User):
        secret=xdh.calc_shared_secret(self.dhPriv, dhk, p)
        xtKey=xdh.derive_key(secret)
        newuser=[name,dhk,gk,xtKey,User]

        self.users.append(newuser)



    

class User:
    def __init__(self,name,op,opDH,opEG):
        self.dhPriv,self.dhPub,self.gPriv,self.gPub=keyGen() # generating keys
        self.name=name # name of phone user
        self.inbox=[]#list of unread messages
        self.cList=[]#[i][0]=name [i][1]=DH key [i][2]=el gamal public key [i][3]=XTEA key
        self.op=op # the user's phone operator
        self.opDH=opDH #the phone operator's DH key
        self.opEG=opEG #the phone operator's el gamal key
        secret=xdh.calc_shared_secret(self.dhPriv, opDH, p)
        self.opXT=xdh.derive_key(secret)
        op.addUser(name, self.dhPub, self.gPub,self)
    
    #add incoming message to user's inbox
    def addToInbox(self, contact, encrypted_msg, s, r):
        #Retrieiving contact from contact list
        con=self.isContact(contact)
        #if contact isn't added, don't add message to inbox
        if con is None:
            return False
        
        
        
        
        #decrypt message using XTEA KEY previously established with contact
        decrypted_msg = xdh.decrypt_message(encrypted_msg, con[3])
        #verify message authenticity with el gamal 
        
        trueSig=eg.verifySignature(con[2], decrypted_msg, s, r)
        
        ####FOR INTERNAL TESTING ONLY
        print(MAGENTA)
        print(f"\n\nmessage being received: {encrypted_msg}\nel gamal s and r:\ns={s}\nr={r}\npublic gamal signature used for verification=\n={con[2]}\nxtkey used for decryption={con[3]}\n\n\n\n")
        print(RESET)
        ###END OF INTERNAL TEST
        if (trueSig):
            #if message is truly from contact, add it to inbox
            self.inbox.append(decrypted_msg)
            return True
        return False
        


    #print out the messages in the User's inbox
    def readInbox(self):
        inlen=len(self.inbox)
        print(f"{self.name}, you have {inlen} message(s):")
        for msg in self.inbox:
            print(f"message: {msg}")
        #empty out inbox after reading messages
        self.inbox=[]
    
    
    
    #finding the given contact in the contact list
    def isContact(self, contact):
        for c in self.cList:
            if (c[0]==contact):
                return c
        return None
    
    #adding contact to contact list, as well as generating XTEA keys for secure communication
    #the flag notifies when the function was called internally or externally.
    def addContact(self,contact,flag=False):
     
        
     
        #checking if the contact is already in the user list.
        for c in self.cList:
            if c[0]==contact:
                #if the contact exists there is no need to add it. exiting function
                return False
        
        
        
        #contact DH key retrieval from operator
        dhk=self.op.getDH(contact)
        
        #contact Gamal key retrival from operator
        gk=self.op.getGAMAL(contact)

        #get the shared secret number from the user's private DH key and the contact's public DH key
        secret=xdh.calc_shared_secret(self.dhPriv, dhk, p)
        
        #generate the XTEA key using the shared secret of the DH key
        xtKey=xdh.derive_key(secret)
        
        
        #creating new contact
        newcon=[contact,dhk,gk,xtKey]
        self.cList.append(newcon)
        #if this user initially called the addContact function, the contact will then have this User's contact info back.
        if not flag:
            con=self.op.getUser(contact)
            con.addContact(self.name,True)
            
            
        #FOR INTERNAL TESTING ONLY
        print(RED)
        print(f"private DH key used for establishing XT key:{self.dhPriv}\npublic key used for establishing XT key: {dhk}\nestablished XTEA key:{xtKey}")
        
        print(RESET)
        # END INTERNAL TEST
        
        
    
    #sending a text message to the contact
    def sendMessage(self,msg,contact):
        
        # ## FOR TESTING PURPOSES ONLY PART
        # #printing the non-encrypted text in hex to compare to encrypted text captured by airwaves
        # print(f"unencrypted hexadecimal of message: {(msg.encode()).hex()}")
        # #END OF TEST AREA
        
        # signing message using EC el gamal
        s,r=eg.signMessage(self.gPriv,msg)
        #getting the contact from contact List
        con=self.isContact(contact)
        #if the contact doesn't exist, add it to contacts list
        if con is None:
            self.addContact(contact)
            con=self.isContact(contact)
        #conkey=the shared XTEA Key
        conkey=con[3]
        #the encrypted msg the will be sent through public channels.
        encrypted_msg = xdh.encrypt_message(msg, conkey)
        
        
        #FOR INTERNAL TESTING ONLY
        print(GREEN)
        
        print(f"\nthe message being sent: {msg}\nThe encrypted message being sent: {encrypted_msg}\ns and r from el gamal\ns={s}\nr={r}\nThe XTEA key used to encrypt the message: {conkey}")
        print(f"\nprivate gamal signature used to sign message:\n {self.gPriv}\n\n\n")
        print(RESET)
        # END INTERNAL TEST
        
        #sending message through the public airwaves
        #
        publicAirwaves(self.name, encrypted_msg, contact, s, r)
    
    




### MAIN. demonstration of a chat between 2 people.     

op=Operator()

#Creating users

Alice=User("Alice",op,op.getOPDH(),op.getOPGAMAL())
Bob=User("Bob",op,op.getOPDH(),op.getOPGAMAL())




#Alice mode



msg1="Hello, This is Alice"
Alice.sendMessage(msg1, "Bob")



#Bob mode
Bob.readInbox()
msg2="Hey alice, i just received your message"
Bob.sendMessage(msg2,"Alice")



#Alice mode
Alice.readInbox()




# ### the infinite loop

# inp=0
# print("entering message terminal, type qqq to exit messaging mode and then terminal mode to exit and terminate program")
# while (inp!='qqq'):
#     user=input("Who is using the terminal, Bob or Alice?")
#     recp=input("Who is the recipient")

#     msg=0
#     #while (msg!='qqq'):
        





        
        
        
        