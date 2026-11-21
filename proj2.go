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

// Definição de estrutura para um registro de usuário.
// A senha NÃO é armazenada: apenas chaves derivadas dela.
// Tudo aqui é cifrado e autenticado antes de ir ao datastore.
type User struct {
	Username string
	FileKey  []byte // raiz para derivar tudo relacionado a arquivos
	PKEDec   userlib.PKEDecKey
	DSSign   userlib.DSSignKey
	// Para JSON serializar/desserializar, os campos precisam
	// ser públicos (começar com letra maiúscula)
}

// Isso cria um usuário. Será chamado apenas uma vez por usuário.
//
// Persistência: o registro completo fica no datastore (cifrado + HMAC),
// em um UUID derivado de usuário+senha; as chaves públicas ficam no
// keystore. Nada depende de memória do processo.
func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("Usuário vazio")
	}
	if password == "" {
		return nil, errors.New("Senha vazia")
	}

	// Chave raiz e derivações (UUID do registro, chave de cifra, chave de MAC, raiz de arquivos)
	root := userlib.Argon2Key([]byte(password), []byte(username), 16)

	uuidBytes, err := userlib.HMACEval(root, []byte("user-uuid"))
	if err != nil {
		return nil, err
	}
	recordUUID := bytesToUUID(uuidBytes)

	encFull, err := userlib.HMACEval(root, []byte("user-enc"))
	if err != nil {
		return nil, err
	}
	macFull, err := userlib.HMACEval(root, []byte("user-mac"))
	if err != nil {
		return nil, err
	}
	fileFull, err := userlib.HMACEval(root, []byte("user-files"))
	if err != nil {
		return nil, err
	}
	encKey := encFull[:16]
	macKey := macFull[:16]

	// Usuário já existe
	if _, exists := userlib.DatastoreGet(recordUUID); exists {
		return nil, errors.New("Usuário já existe")
	}
	if _, exists := userlib.KeystoreGet(username + "_pke"); exists {
		return nil, errors.New("Usuário já existe")
	}

	// Chaves de criptografia (RSA) e de assinatura digital
	pkeEnc, pkeDec, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	dsSign, dsVerify, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Chaves PÚBLICAS no keystore
	if err = userlib.KeystoreSet(username+"_pke", pkeEnc); err != nil {
		return nil, err
	}
	if err = userlib.KeystoreSet(username+"_ds", dsVerify); err != nil {
		return nil, err
	}

	user := User{
		Username: username,
		FileKey:  fileFull[:16],
		PKEDec:   pkeDec,
		DSSign:   dsSign,
	}

	// Serializa o registro COMPLETO, cifra e anexa HMAC (encrypt-then-MAC)
	serialized, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	uPadLen := userlib.AESBlockSize - len(serialized)%userlib.AESBlockSize
	uPadded := append([]byte{}, serialized...)
	for k := 0; k < uPadLen; k++ {
		uPadded = append(uPadded, byte(uPadLen))
	}
	ct := userlib.SymEnc(encKey, iv, uPadded)
	tag, err := userlib.HMACEval(macKey, append([]byte("user:"+username), ct...))
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(recordUUID, append(ct, tag...))

	return &user, nil
}

// Isso recupera as informações do usuário do Datastore.
// Falha se usuário/senha forem inválidos, se os dados estiverem
// corrompidos ou se o usuário não existir.
func GetUser(username string, password string) (userdataptr *User, err error) {
	if username == "" || password == "" {
		return nil, errors.New("Usuário ou senha inválidos")
	}

	// Mesmas derivações de InitUser
	root := userlib.Argon2Key([]byte(password), []byte(username), 16)

	uuidBytes, err := userlib.HMACEval(root, []byte("user-uuid"))
	if err != nil {
		return nil, err
	}
	recordUUID := bytesToUUID(uuidBytes)

	encFull, err := userlib.HMACEval(root, []byte("user-enc"))
	if err != nil {
		return nil, err
	}
	macFull, err := userlib.HMACEval(root, []byte("user-mac"))
	if err != nil {
		return nil, err
	}
	encKey := encFull[:16]
	macKey := macFull[:16]

	blob, ok := userlib.DatastoreGet(recordUUID)
	if !ok {
		return nil, errors.New("Dados de usuário não encontrados")
	}

	// Primeiro verifica integridade (senha errada também falha aqui)...
	if len(blob) < 64+userlib.AESBlockSize {
		return nil, errors.New("Dados de usuário corrompidos")
	}
	ct := blob[:len(blob)-64]
	tag := blob[len(blob)-64:]
	expected, err := userlib.HMACEval(macKey, append([]byte("user:"+username), ct...))
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(expected, tag) {
		return nil, errors.New("Usuário ou senha inválidos, ou dados corrompidos")
	}

	// ...e só então decifra e decodifica
	plain := userlib.SymDec(encKey, ct)
	if len(plain) == 0 || plain[len(plain)-1] == 0 || int(plain[len(plain)-1]) > userlib.AESBlockSize || int(plain[len(plain)-1]) > len(plain) {
		return nil, errors.New("Dados de usuário corrompidos")
	}
	plain = plain[:len(plain)-int(plain[len(plain)-1])]
	var user User
	if err = json.Unmarshal(plain, &user); err != nil {
		return nil, errors.New("Dados de usuário corrompidos")
	}
	if user.Username != username {
		return nil, errors.New("Dados de usuário corrompidos")
	}

	return &user, nil
}

// Modelo de dados dos arquivos:
//   - Cabeçalho (1 por arquivo): guarda apenas o número de blocos.
//   - Bloco i (1 por Store/Append): fica em um UUID derivado de
//     (chave do arquivo, i). O Append só escreve o novo bloco e
//     atualiza o cabeçalho (tamanho constante), sem reler nem
//     recriptografar o conteúdo anterior.
//   - Tudo é cifrado + autenticado; o MAC de cada bloco cobre sua
//     posição, impedindo troca de blocos. O nome do arquivo só entra
//     em HMACs e nunca aparece no datastore.
//
// Chaves/UUIDs por arquivo (em todas as funções abaixo):
//   base = HMAC(FileKey, "file:"+filename)
//   base[0:16]  -> UUID do cabeçalho
//   base[16:32] -> chave de cifra
//   base[32:48] -> chave de MAC
//   base[48:64] -> semente dos UUIDs dos blocos

// Isso armazena um arquivo no datastore.
//
// O nome do arquivo NÃO é revelado ao datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	base, err := userlib.HMACEval(userdata.FileKey, []byte("file:"+filename))
	if err != nil {
		return
	}
	headerUUID := bytesToUUID(base[:16])
	encKey := base[16:32]
	macKey := base[32:48]
	blockSeed := base[48:64]

	// Bloco 0
	idx, err := json.Marshal(0)
	if err != nil {
		return
	}
	aad := append([]byte("block:"), idx...)
	blockID, err := userlib.HMACEval(blockSeed, aad)
	if err != nil {
		return
	}
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	dPadLen := userlib.AESBlockSize - len(data)%userlib.AESBlockSize
	dPadded := append([]byte{}, data...)
	for k := 0; k < dPadLen; k++ {
		dPadded = append(dPadded, byte(dPadLen))
	}
	ct := userlib.SymEnc(encKey, iv, dPadded)
	tag, err := userlib.HMACEval(macKey, append(append([]byte{}, aad...), ct...))
	if err != nil {
		return
	}
	userlib.DatastoreSet(bytesToUUID(blockID), append(ct, tag...))

	// Cabeçalho
	header, err := json.Marshal(map[string]int{"NumBlocks": 1})
	if err != nil {
		return
	}
	iv = userlib.RandomBytes(userlib.AESBlockSize)
	hPadLen := userlib.AESBlockSize - len(header)%userlib.AESBlockSize
	hPadded := append([]byte{}, header...)
	for k := 0; k < hPadLen; k++ {
		hPadded = append(hPadded, byte(hPadLen))
	}
	ct = userlib.SymEnc(encKey, iv, hPadded)
	tag, err = userlib.HMACEval(macKey, append([]byte("header"), ct...))
	if err != nil {
		return
	}
	userlib.DatastoreSet(headerUUID, append(ct, tag...))
}

// Isso adiciona dados a um arquivo existente, sem reescrever o conteúdo anterior.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	base, err := userlib.HMACEval(userdata.FileKey, []byte("file:"+filename))
	if err != nil {
		return err
	}
	headerUUID := bytesToUUID(base[:16])
	encKey := base[16:32]
	macKey := base[32:48]
	blockSeed := base[48:64]

	// Lê e valida o cabeçalho
	blob, ok := userlib.DatastoreGet(headerUUID)
	if !ok {
		return errors.New("arquivo inexistente")
	}
	if len(blob) < 64+userlib.AESBlockSize {
		return errors.New("arquivo ou metadados corrompidos")
	}
	ct := blob[:len(blob)-64]
	tag := blob[len(blob)-64:]
	expected, err := userlib.HMACEval(macKey, append([]byte("header"), ct...))
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(expected, tag) {
		return errors.New("arquivo ou metadados corrompidos")
	}
	plain := userlib.SymDec(encKey, ct)
	if len(plain) == 0 || plain[len(plain)-1] == 0 || int(plain[len(plain)-1]) > userlib.AESBlockSize || int(plain[len(plain)-1]) > len(plain) {
		return errors.New("arquivo ou metadados corrompidos")
	}
	plain = plain[:len(plain)-int(plain[len(plain)-1])]
	var header map[string]int
	if err = json.Unmarshal(plain, &header); err != nil {
		return errors.New("arquivo ou metadados corrompidos")
	}
	n := header["NumBlocks"]
	if n < 1 {
		return errors.New("arquivo ou metadados corrompidos")
	}

	// Escreve apenas o novo bloco (posição n)
	idx, err := json.Marshal(n)
	if err != nil {
		return err
	}
	aad := append([]byte("block:"), idx...)
	blockID, err := userlib.HMACEval(blockSeed, aad)
	if err != nil {
		return err
	}
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	bPadLen := userlib.AESBlockSize - len(data)%userlib.AESBlockSize
	bPadded := append([]byte{}, data...)
	for k := 0; k < bPadLen; k++ {
		bPadded = append(bPadded, byte(bPadLen))
	}
	bct := userlib.SymEnc(encKey, iv, bPadded)
	btag, err := userlib.HMACEval(macKey, append(append([]byte{}, aad...), bct...))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(bytesToUUID(blockID), append(bct, btag...))

	// Atualiza o cabeçalho
	newHeader, err := json.Marshal(map[string]int{"NumBlocks": n + 1})
	if err != nil {
		return err
	}
	iv = userlib.RandomBytes(userlib.AESBlockSize)
	nhPadLen := userlib.AESBlockSize - len(newHeader)%userlib.AESBlockSize
	nhPadded := append([]byte{}, newHeader...)
	for k := 0; k < nhPadLen; k++ {
		nhPadded = append(nhPadded, byte(nhPadLen))
	}
	hct := userlib.SymEnc(encKey, iv, nhPadded)
	htag, err := userlib.HMACEval(macKey, append([]byte("header"), hct...))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(headerUUID, append(hct, htag...))
	return nil
}

// Isso carrega um arquivo do Datastore.
//
// Retorna um erro se o arquivo não existir ou estiver corrompido.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	base, err := userlib.HMACEval(userdata.FileKey, []byte("file:"+filename))
	if err != nil {
		return nil, err
	}
	headerUUID := bytesToUUID(base[:16])
	encKey := base[16:32]
	macKey := base[32:48]
	blockSeed := base[48:64]

	// Lê e valida o cabeçalho
	blob, ok := userlib.DatastoreGet(headerUUID)
	if !ok {
		return nil, errors.New("arquivo inexistente")
	}
	if len(blob) < 64+userlib.AESBlockSize {
		return nil, errors.New("arquivo ou metadados corrompidos")
	}
	ct := blob[:len(blob)-64]
	tag := blob[len(blob)-64:]
	expected, err := userlib.HMACEval(macKey, append([]byte("header"), ct...))
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(expected, tag) {
		return nil, errors.New("arquivo ou metadados corrompidos")
	}
	plain := userlib.SymDec(encKey, ct)
	if len(plain) == 0 || plain[len(plain)-1] == 0 || int(plain[len(plain)-1]) > userlib.AESBlockSize || int(plain[len(plain)-1]) > len(plain) {
		return nil, errors.New("arquivo ou metadados corrompidos")
	}
	plain = plain[:len(plain)-int(plain[len(plain)-1])]
	var header map[string]int
	if err = json.Unmarshal(plain, &header); err != nil {
		return nil, errors.New("arquivo ou metadados corrompidos")
	}
	n := header["NumBlocks"]
	if n < 1 {
		return nil, errors.New("arquivo ou metadados corrompidos")
	}

	// Lê, valida e concatena os blocos na ordem
	result := []byte{}
	for i := 0; i < n; i++ {
		idx, err := json.Marshal(i)
		if err != nil {
			return nil, err
		}
		aad := append([]byte("block:"), idx...)
		blockID, err := userlib.HMACEval(blockSeed, aad)
		if err != nil {
			return nil, err
		}
		bblob, ok := userlib.DatastoreGet(bytesToUUID(blockID))
		if !ok || len(bblob) < 64+userlib.AESBlockSize {
			return nil, errors.New("arquivo corrompido")
		}
		bct := bblob[:len(bblob)-64]
		btag := bblob[len(bblob)-64:]
		bexpected, err := userlib.HMACEval(macKey, append(append([]byte{}, aad...), bct...))
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(bexpected, btag) {
			return nil, errors.New("arquivo corrompido")
		}
		bplain := userlib.SymDec(encKey, bct)
		if len(bplain) == 0 || bplain[len(bplain)-1] == 0 || int(bplain[len(bplain)-1]) > userlib.AESBlockSize || int(bplain[len(bplain)-1]) > len(bplain) {
			return nil, errors.New("arquivo corrompido")
		}
		result = append(result, bplain[:len(bplain)-int(bplain[len(bplain)-1])]...)
	}
	return result, nil
}

// Você pode querer definir o que exatamente deseja passar como
// sharingRecord para serializar/desserializar no datastore.
type sharingRecord struct {
}

// (Compartilhamento ainda não implementado)
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Remove o acesso de todos os outros.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
