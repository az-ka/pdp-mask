package scan

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkScanCSV_10k_Rows(b *testing.B) {
	tempDir := b.TempDir()
	path := filepath.Join(tempDir, "bench_10k.csv")
	file, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	writer := csv.NewWriter(file)
	headers := []string{"id", "name", "email", "phone", "nik", "status", "created_at"}
	if err := writer.Write(headers); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		row := []string{
			fmt.Sprintf("%d", i),
			"User Name",
			fmt.Sprintf("user_%d@example.test", i),
			fmt.Sprintf("08123456%04d", i%10000),
			fmt.Sprintf("317305010190%04d", i%10000),
			"active",
			"2024-01-01T00:00:00Z",
		}
		if err := writer.Write(row); err != nil {
			b.Fatal(err)
		}
	}
	writer.Flush()
	file.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ScanCSV(path, CSVOptions{SampleRows: 500})
		if err != nil {
			b.Fatal(err)
		}
	}
}
