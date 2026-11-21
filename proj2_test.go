package proj2

// Você NÃO PODE alterar o que é importado. Se você adicionar QUALQUER
// importação adicional, o corretor automático quebrará.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/RafaelTupynamba/Projeto2/userlib"
	_ "github.com/google/uuid"
)

func TestInit(t *testing.T) {
	t.Log("Teste de inicialização")

	// Talvez você queira desativar isso em algum momento
	userlib.SetDebugStatus(true)
	//someUsefulThings() //  Não chame someUsefulThings() no corretor automático, caso um aluno a remova
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error indica que o teste falhou
		t.Error("Falha ao inicializar usuário", err)
		return
	}
	// t.Log() apenas produz saída se você executar com "go test -v"
	t.Log("Usuário obtido", u)
	// Se você quiser comentar a linha acima,
	// escreva _ = u aqui para satisfazer o compilador
	// Provavelmente você quer muitos testes a mais aqui.
}

func TestStorage(t *testing.T) {
	// E alguns testes a mais, porque
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Falha ao recarregar usuário", err)
		return
	}
	t.Log("Usuário carregado", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Falha ao enviar e baixar", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("O arquivo baixado não é o mesmo", v, v2)
		return
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Falha ao recarregar usuário", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Falha ao inicializar bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Falha ao baixar o arquivo de alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Falha ao compartilhar um arquivo", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Falha ao receber a mensagem de compartilhamento", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Falha ao baixar o arquivo após o compartilhamento", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("O arquivo compartilhado não é o mesmo", v, v2)
		return
	}

}
