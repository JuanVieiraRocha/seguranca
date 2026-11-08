package proj2

import(
	// "fmt"
	// "bufio"
	// "os"
	"errors"
	"github.com/RafaelTupynamba/Projeto2/userlib"
	"github.com/google/uuid"
	"crypto/sha512"
)

// Estrutura de Dados do User à ser Armazenado

type User struct {
	Username string
	UUID userlib.UUID
	Salt []byte
	IV []byte
	PKEPrivate userlib.PrivateKeyType
	DSPrivate userlib.DSVerifyKey
}


func InitUser(username string, password string)(user *User, err error){

	if username ==""{
		return nil, errors.New("usuário vazio")

	}
	if password == ""{
		return nil, errors.New("Senha Vazia")
	}

	// Variaveis da UserLib
	_, pkePrivate, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	_, dsPrivate, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	// Desenvolvimento da chave RSA
	salt := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(userlib.AESBlockSize)

	key := userlib.Argon2Key([]byte(password), salt, uint32(userlib.AESKeySize))
	byte_slice_hash := sha512.Sum512([]byte(username))
	new_UUID, _ := uuid.FromBytes(byte_slice_hash[:16])
	user = &User{
		Username:   username,
		UUID:       new_UUID,
		Salt:       salt,
		IV:         iv,
		PKEPrivate: pkePrivate,
		DSPrivate:  dsPrivate,
	}

	_,valid:= userlib.DatastoreGet(new_UUID)
	if valid{
		return nil, errors.New ("usuário já existe")
	}

	// Tornando o usuario em uma string
	serializedUser := make([]byte, len(username)+16)
	copy(serializedUser, []byte(username))

	cipherText := userlib.SymEnc(key, iv, serializedUser)
	userlib.DatastoreSet(new_UUID, cipherText)

	return user, nil
}