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
	Passowrd        string
	Uuid            userlib.UUID
	ChaveEncriptada userlib.PKEDecKey
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
	var usuarioLogado User

	// Verifica se há usuario e senha
	if username == "" {
		return nil, errors.New("Usuário Vazio")
	}
	if password == "" {
		return nil, errors.New("Senha Vazia")
	}

	// userlib, linha 31, 58, 277, 305

	key := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize))

	res, HMACEerr := userlib.HMACEval(key, []byte(username)) // Pesquisar o que é a RES
	if HMACEerr != nil {
		return nil, HMACEerr
	}
	// cria o userUUID

	userUUID := bytesToUUID(res)

	// Identidade RSA, para acessar posteriormente

	// Chave de criptografia
	_, decriptedres, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	// Chave de descriptografia
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Salvando usuário
	usuarioLogado.Username = username
	usuarioLogado.Passowrd = password
	usuarioLogado.Uuid = userUUID
	usuarioLogado.ChaveEncriptada = decriptedres
	usuarioLogado.Assinatura = signKey
	usuarioLogado.Salt = key

	// Salvando chave de recuperação

	userlib.KeystoreSet(username, verifyKey)

	// Transforma usuário em JSON, IV aleatório, criptografar JSON

	userSerialized, err := json.Marshal(usuarioLogado)
	if err != nil {
		return nil, err
	}
	diferencaDeBytes := userlib.AESBlockSize - len(userSerialized)%userlib.AESBlockSize
	cabecalhoEspacado := append([]byte{}, userSerialized...)
	for i := 0; i < diferencaDeBytes; i++ {
		cabecalhoEspacado = append(cabecalhoEspacado, byte(diferencaDeBytes))
	}

	iv := userlib.RandomBytes(userlib.AESBlockSize)
	cipherText := userlib.SymEnc(key, iv, cabecalhoEspacado)
	identificadorDeArquivo, err := userlib.HMACEval(key, append([]byte("usuário:"+username), cipherText...))
	if err != nil {
		return nil, err
	}
	// Armazenando
	userlib.DatastoreSet(userUUID, append(cipherText, identificadorDeArquivo...))

	return &usuarioLogado, nil
}

// Isso recupera as informações do usuário do Datastore.
// Deve falhar com um erro se o usuário/senha for inválido,
// se os dados do usuário estiverem corrompidos,
// ou se o usuário não for encontrado.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var usuarioLogado User

	// erro: Usuário ou senha inválido
	if username == "" || password == "" {
		return nil, errors.New("Esse nome e essa senha não existem seu borocoxo")
	}

	// Derivando UUID
	key := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize))
	res, err := userlib.HMACEval(key, []byte(username)) // Pesquisar o que é a RES
	if err != nil {
		return nil, err
	}
	userUUID := bytesToUUID(res)

	// Verificando a integridade das cosa

	usuarioNoBanco, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("Dados de usuário não encontrados")
	}
	if len(usuarioNoBanco) < userlib.AESBlockSize+len(res) {
		return nil, errors.New("Dados de usuário corrompidos")
	}

	cipherText := usuarioNoBanco[:len(usuarioNoBanco)-len(res)]
	identificadorDeArquivo := usuarioNoBanco[len(usuarioNoBanco)-len(res):]

	esperado, err := userlib.HMACEval(key, append([]byte("usuário:"+username), cipherText...))
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(esperado, identificadorDeArquivo) {
		return nil, errors.New("Usuário ou senha inválidos, ou dados corrompidos")
	}

	// Decodificando...
	plainText := userlib.SymDec(key, cipherText) // Retorna um byte, que é o ciphertext;plaintext
	if len(plainText) == 0 || plainText[len(plainText)-1] == 0 || int(plainText[len(plainText)-1]) > userlib.AESBlockSize || int(plainText[len(plainText)-1]) > len(plainText) {
		return nil, errors.New("Dados de usuário corrompidos")
	}
	// Verificando se a senha está correta
	plainText = plainText[:len(plainText)-int(plainText[len(plainText)-1])]

	JSONerror := json.Unmarshal(plainText, &usuarioLogado)
	if JSONerror != nil {
		return nil, errors.New("senha ou usuário inválidos")
	}
	return &usuarioLogado, nil
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

	// UUID cabeçalho
	chaveDoCabecalho, err := userlib.HMACEval(userdata.Salt, append([]byte("cabeçalho:"), fileSpecificUser...))
	if err != nil {
		return
	}
	// chaves do arquivo
	fileKey := chaveDoCabecalho[:16]
	cabecalhoUUID := bytesToUUID(fileKey)
	fileUUID := uuid.New()

	// criptografando informações
	diferencaDeBytes := userlib.AESBlockSize - len(data)%userlib.AESBlockSize
	infoEspacada := append([]byte{}, data...)
	for i := 0; i < diferencaDeBytes; i++ {
		infoEspacada = append(infoEspacada, byte(diferencaDeBytes))
	}

	iv := userlib.RandomBytes(userlib.AESBlockSize)
	cipherText := userlib.SymEnc(fileKey, iv, infoEspacada)

	// Salvando a data

	userlib.DatastoreSet(fileUUID, cipherText)

	// para a leitura do LoadFile
	cabecalhoEmJSON, err := json.Marshal(struct{ Blocks []uuid.UUID }{Blocks: []uuid.UUID{fileUUID}})
	if err != nil {
		return
	}
	diferencaDoCabecalho := userlib.AESBlockSize - len(cabecalhoEmJSON)%userlib.AESBlockSize
	cabecalhoEspacado := append([]byte{}, cabecalhoEmJSON...)
	for i := 0; i < diferencaDoCabecalho; i++ {
		cabecalhoEspacado = append(cabecalhoEspacado, byte(diferencaDoCabecalho))
	}
	iv = userlib.RandomBytes(userlib.AESBlockSize)
	userlib.DatastoreSet(cabecalhoUUID, userlib.SymEnc(fileKey, iv, cabecalhoEspacado))

}

// Isso adiciona dados a um arquivo existente.
//
// Append deve ser eficiente: você não deve reescrever ou recriptografar
// o arquivo existente, mas apenas a informação adicional
// e metadados necessários.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Chaves de identificação
	fileSpecificUser := []byte(userdata.Username + ":" + filename)
	chaveDeArquivo, HMAErr := userlib.HMACEval(userdata.Salt, fileSpecificUser)
	if HMAErr != nil {
		return HMAErr
	}

	fileUUID := bytesToUUID(chaveDeArquivo[16:32])
	chaveDeAdicao := bytesToUUID(chaveDeArquivo[:16])
	fileKey := chaveDeArquivo[:16]

	// Descriptografando data
	nomeEncriptado, exists := userlib.DatastoreGet(fileUUID)
	if !exists {
		return errors.New("arquivo Inexistente")
	}
	plainText := userlib.SymDec(fileKey, nomeEncriptado)
	if len(plainText) == 0 {
		return errors.New("Arquivo ou metadados corrompidos")
	}

	// Salvando dados
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	userlib.DatastoreSet(
		chaveDeAdicao,
		userlib.SymEnc(fileKey, iv, data),
	)

	novoNome, err := json.Marshal(plainText)
	if err != nil {
		return err
	}

	iv = userlib.RandomBytes(userlib.AESBlockSize)
	userlib.DatastoreSet(
		fileUUID,
		userlib.SymEnc(fileKey, iv, novoNome),
	)
	return
}

// Isso carrega um arquivo do Datastore.
//
// Deve retornar um erro se o arquivo estiver corrompido de qualquer forma.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileSpecificUser := []byte(userdata.Username + ":" + filename)
	chaveDoCabecalho, err := userlib.HMACEval(userdata.Salt, append([]byte("cabeçalho:"), fileSpecificUser...))
	if err != nil {
		return nil, err
	}

	// Mesma chave usada no StoreFile para o cabeçalho
	headerKey := chaveDoCabecalho[:16]
	headerUUID := bytesToUUID(headerKey)

	ciphertext, exists := userlib.DatastoreGet(headerUUID)
	if !exists {
		return nil, errors.New("Arquivo não encontrado")
	}
	if len(ciphertext) < 2*userlib.AESBlockSize || len(ciphertext)%userlib.AESBlockSize != 0 {
		return nil, errors.New("Arquivo ou Metadados Corrompidos")
	}

	headerJSON := userlib.SymDec(headerKey, ciphertext)
	if len(headerJSON) == 0 || headerJSON[len(headerJSON)-1] == 0 || int(headerJSON[len(headerJSON)-1]) > userlib.AESBlockSize || int(headerJSON[len(headerJSON)-1]) > len(headerJSON) {
		return nil, errors.New("Arquivo ou Metadados Corrompidos")
	}
	headerJSON = headerJSON[:len(headerJSON)-int(headerJSON[len(headerJSON)-1])]

	type fileHeader struct {
		Blocks []uuid.UUID
	}

	var header fileHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("Arquivo ou Metadados Corrompidos")
	}

	var result []byte
	for _, blockUUID := range header.Blocks {
		blockCiphertext, exists := userlib.DatastoreGet(blockUUID)
		if !exists {
			return nil, errors.New("Arquivo Corrompido")
		}
		if len(blockCiphertext) < 2*userlib.AESBlockSize || len(blockCiphertext)%userlib.AESBlockSize != 0 {
			return nil, errors.New("Arquivo Corrompido")
		}

		// Se no StoreFile o bloco foi cifrado com headerKey, use headerKey aqui também
		blockPlain := userlib.SymDec(headerKey, blockCiphertext)
		if len(blockPlain) == 0 || blockPlain[len(blockPlain)-1] == 0 || int(blockPlain[len(blockPlain)-1]) > userlib.AESBlockSize || int(blockPlain[len(blockPlain)-1]) > len(blockPlain) {
			return nil, errors.New("Arquivo Corrompido")
		}
		result = append(result, blockPlain[:len(blockPlain)-int(blockPlain[len(blockPlain)-1])]...)
	}

	return result, nil
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
