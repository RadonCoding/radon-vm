namespace radon_vm {
    internal class Program {
        private static void Main(string[] args) {
            string inputPath = args[0];
            string? inputDir = Path.GetDirectoryName(inputPath);

            if (string.IsNullOrEmpty(inputDir)) {
                return;
            }
            string outputDir = Path.Combine(inputDir, "Protected");

            if (Directory.Exists(outputDir)) {
                Directory.Delete(outputDir, true);
            }
            Directory.CreateDirectory(outputDir);

            string outputPath = Path.Combine(outputDir, Path.GetFileName(inputPath));

            File.Copy(inputPath, outputPath, true);

            Compiler compiler = new Compiler(outputPath);
            compiler.Protect();
            compiler.Save();
        }
    }
}