from ecdsa import scalarmult, curve_secp256r1

pk = "101294504421271640558507005999297917358807428420182448449484311550690376520677"   #extracter private key using colcalc.com

print(scalarmult(curve_secp256r1.g, int(pk), curve_secp256r1))
