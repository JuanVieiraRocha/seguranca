package proj2

// Você NÃO PODE alterar o que é importado. Se você adicionar QUALQUER
// importação adicional, o corretor automático quebrará.

import (
	// Você pode obter os pacotes necessários com
	// go mod download
	"github.com/RafaelTupynamba/Projeto2/userlib"

	// A vida fica muito mais fácil com json: você
	// vai querer usar isso para transformar facilmente
	// estruturas complexas em strings etc...
	"encoding/json"

	// Igualmente útil para depuração etc.
	"encoding/hex"

	// UUIDs são gerados com base no RNG criptográfico,
	// então vamos facilitar a vida e usar esses também...
	//
	"github.com/google/uuid"

	// Útil para mensagens de depuração ou manipulação de strings para chaves do datastore
	"strings"

	// Importação de errors
	"errors"

	// opcional
	_ "strconv"
	// Se você está procurando fmt, não fornecemos fmt, mas você pode usar userlib.DebugMsg
	// veja someUsefulThings() abaixo
)

// Esta função serve a dois propósitos: mostra alguns primitivos úteis
// e suprime avisos de itens que não estão sendo usados
func someUsefulThings() {
	// Cria um UUID aleatório
	f := uuid.New()
	userlib.DebugMsg("UUID como string:%v", f.String())

	// Exemplo de sobrescrever um byte de f
	f[0] = 10
	userlib.DebugMsg("UUID como string:%v", f.String())

	// Toma uma sequência de bytes e renderiza como hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("O hex: %v", h)

	// Serializa dados em uma representação JSON
	// Funciona também com estruturas Go
	d, _ := json.Marshal(f)
	userlib.DebugMsg("Os dados JSON: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Dados desserializados %v", g.String())

	// Isso cria um tipo de erro
	userlib.DebugMsg("Criação de erro %v", errors.New(strings.ToTitle("Isso é um erro")))

	// E uma chave RSA aleatória. Neste caso, ignorando o
	// valor de retorno do erro
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("A chave é %v, %v", pk, sk)
}

// Função auxiliar: toma os primeiros 16 bytes
// e converte no tipo UUID
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// Definição de estrutura para um registro de usuário
type User struct {
	Username        string
	Uuid            userlib.UUID
	UhaveEncriptada userlib.PKEDecKey
	Assinatura      userlib.DSSignKey
	Salt            []byte
	// Você pode adicionar outros campos aqui, se quiser...
	// Para JSON serializar/desserializar, os campos precisam
	// ser públicos (começar com letra maiúscula)
}

// Isso cria um usuário. Será chamado apenas uma vez por usuário
// (a menos que o keystore e o datastore sejam limpos durante testes).

// Deve armazenar uma cópia dos dados do usuário, devidamente criptografada,
// no datastore e deve armazenar a chave pública do usuário no keystore.

// O datastore pode corromper ou completamente apagar as informações
// armazenadas, mas ninguém de fora deve conseguir acessar os dados
// do usuário armazenados: o nome usado no datastore não deve ser
// descoberto sem também conhecer a senha e o nome de usuário.

// Não é permitido usar qualquer armazenamento global diferente
// do keystore e das funções de datastore da biblioteca userlib.

// Pode-se assumir que o usuário possui uma senha FORTE
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Erros localizados como <nomeDaFunção>err
	var userdata User
	userdataptr = &userdata

	if username == "" {
		return nil, errors.New("Usuário Vazio")
	}
	if password == "" {
		return nil, errors.New("Senha Vazia")
	}

	// userlib, linha 31, 58, 277, 305

	salt := []byte(username)
	key := userlib.Argon2Key([]byte(password), salt, uint32(userlib.AESKeySize))
	res, HMACEerr := userlib.HMACEval(key, []byte(username)) // Pesquisar o que é a RES
	if HMACEerr != nil {
		return nil, HMACEerr
	}
	// cria o userUUID

	userUUID := bytesToUUID(res)

	// Identidade RSA, para acessar posteriormente

	_, decriptedres, keyErr := userlib.PKEKeyGen()
	signKey, verifyKey, sigErr := userlib.DSKeyGen()
	if keyErr != nil {
		return nil, keyErr
	}
	if sigErr != nil {
		return nil, sigErr
	}

	// Salvando usuário
	userdata.Username = username
	userdata.Uuid = userUUID
	userdata.UhaveEncriptada = decriptedres
	userdata.Assinatura = signKey
	userdata.Salt = salt

	// Salvando chave de recuperação

	userlib.KeystoreSet(username, verifyKey)

	// Transforma usuário em JSON, IV aleatório, criptografar JSON
	userSerialized, JSONerr := json.Marshal(userdataptr)
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	if JSONerr != nil {
		return nil, JSONerr
	}
	cipherText := userlib.SymEnc(key, iv, userSerialized)

	// Armazenando
	userlib.DatastoreSet(userUUID, cipherText)

	return &userdata, nil
}

// Isso recupera as informações do usuário do Datastore.
// Deve falhar com um erro se o usuário/senha for inválido,
// se os dados do usuário estiverem corrompidos,
// ou se o usuário não for encontrado.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Derivando UUID
	salt := []byte(username)
	key := userlib.Argon2Key([]byte(password), salt, uint32(userlib.AESKeySize))
	res, HMACEerr := userlib.HMACEval(key, []byte(username)) // Pesquisar o que é a RES
	if HMACEerr != nil {
		return nil, HMACEerr
	}
	// cria o userUUID
	userUUID := bytesToUUID(res)
	// Buscando o usuário no store
	cipherText, ok := userlib.DatastoreGet(userUUID)
	if ok != true {
		return nil, errors.New("Valor inexistente")
	}

	// Descriptografando dados
	plainText := userlib.SymDec(key, cipherText) // Retorna um byte, que é o ciphertext;plaintext

	// Verificando se a senha está correta
	JSONerror := json.Unmarshal(plainText, userdataptr)
	if JSONerror != nil {
		return nil, errors.New("senha ou dados inválidos")
	}

	return userdataptr, nil
}

// Isso armazena um arquivo no datastore.
//
// O nome do arquivo NÃO deve ser revelado ao datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Devo atribuir FileName à Data
	// Filename seria o UUID
	// Diversas pessoas podem ter o mesmo filename
	// Portanto filename deve ser um hash
	// Deve haver verificação de usuário para ler a data

	// Chave especial
	fileSpecificUser := []byte(userdata.Username + ":" + filename)
	chaveDeArquivo, HMAErr := userlib.HMACEval(userdata.Salt, fileSpecificUser)
	if HMAErr != nil {
		return
	}
	fileUUID := bytesToUUID(chaveDeArquivo[:16])

	// Criptografando Data
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	cipherText := userlib.SymEnc(chaveDeArquivo, iv, data)

	// Salvando a data

	userlib.DatastoreSet(fileUUID, cipherText)

}

// Isso adiciona dados a um arquivo existente.
//
// Append deve ser eficiente: você não deve reescrever ou recriptografar
// o arquivo existente, mas apenas a informação adicional
// e metadados necessários.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// Isso carrega um arquivo do Datastore.
//
// Deve retornar um erro se o arquivo estiver corrompido de qualquer forma.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	return
}

// Você pode querer definir o que exatamente deseja passar como
// sharingRecord para serializar/desserializar no datastore.
type sharingRecord struct {
}

// Isso cria um registro de compartilhamento, que é uma chave
// apontando para algo no datastore para compartilhar com o destinatário.

// Isso habilita o destinatário a acessar o arquivo criptografado
// tanto para leitura quanto para append.

// Nota: nem o destinatário NEM o datastore devem obter qualquer
// informação sobre como o remetente chama o arquivo. Apenas o
// destinatário pode acessar o registro de compartilhamento, e apenas
// o destinatário deve ser capaz de saber quem é o remetente.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Nota: o nome do arquivo do destinatário pode ser diferente do nome
// do arquivo do remetente. O destinatário não deve ser capaz de
// descobrir como o remetente vê o nome do arquivo! No entanto, o
// destinatário deve garantir que a mensagem é autenticamente do remetente.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Remove o acesso de todos os outros.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
