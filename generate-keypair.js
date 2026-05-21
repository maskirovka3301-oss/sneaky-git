#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const simpleGit = require('simple-git');

async function generateKeypair() {
  const repoRoot = process.cwd();
  const privateKeyPath = path.join(repoRoot, 'private.pem');
  const publicKeyPath = path.join(repoRoot, 'public.pem');
  const gitignorePath = path.join(repoRoot, '.gitignore');
  
  console.log('\n🔐 Generating RSA keypair in repository root...\n');
  
  // Check if private.pem already exists
  try {
    await fs.access(privateKeyPath);
    console.error('❌ private.pem already exists! Remove it first if you want to regenerate.');
    process.exit(1);
  } catch (err) {
    // File doesn't exist, good to proceed
  }
  
  // Generate 4096-bit RSA keypair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  // Write private.pem
  await fs.writeFile(privateKeyPath, privateKey);
  console.log('✅ Created private.pem');
  
  // Write public.pem
  await fs.writeFile(publicKeyPath, publicKey);
  console.log('✅ Created public.pem');
  
  // Set secure permissions on private key (Unix only)
  try {
    await fs.chmod(privateKeyPath, 0o600);
    console.log('✅ Set secure permissions on private.pem (600)');
  } catch (err) {
    // Ignore on Windows
  }
  
  // Ensure .gitignore has private.pem
  let gitignore = '';
  try {
    gitignore = await fs.readFile(gitignorePath, 'utf8');
  } catch (err) {
    // .gitignore doesn't exist yet
  }
  
  let gitignoreModified = false;
  if (!gitignore.includes('private.pem')) {
    const privateIgnore = '\n# RSA private key - DO NOT COMMIT\nprivate.pem\n';
    await fs.appendFile(gitignorePath, privateIgnore);
    console.log('✅ Added private.pem to .gitignore');
    gitignoreModified = true;
  } else {
    console.log('✅ private.pem already in .gitignore');
  }
  
  // Display key information
  const fingerprint = crypto.createHash('sha256')
    .update(publicKey)
    .digest('hex')
    .match(/.{1,4}/g)
    .join(' ');
  
  console.log('\n✨ Keypair generated successfully!\n');
  console.log(`🔑 Public key fingerprint (SHA-256): ${fingerprint}`);
  
  // Auto-commit public.pem and .gitignore if modified
  try {
    const git = simpleGit(repoRoot);
    
    // Check if we're in a git repository
    const isRepo = await git.checkIsRepo();
    if (!isRepo) {
      console.log('\n⚠️  Not a git repository. Skipping auto-commit.');
      console.log('Please manually commit public.pem');
      return;
    }
    
    // Add files to git
    await git.add('public.pem');
    if (gitignoreModified) {
      await git.add('.gitignore');
    }
    
    // Check if there's anything to commit
    const status = await git.status();
    if (status.files.length === 0) {
      console.log('\n✅ public.pem already committed or no changes to commit');
      return;
    }
    
    // Commit the files
    const commitMessage = 'chore: add public key for signaling system\n\n- Generated RSA 4096-bit public key\n- Public key fingerprint: ' + fingerprint;
    await git.commit(commitMessage);
    console.log('\n✅ Auto-committed public.pem to repository');
    
    // Ask about pushing
    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    const answer = await new Promise((resolve) => {
      rl.question('\n📤 Push to remote? (y/n): ', resolve);
    });
    
    if (answer.toLowerCase() === 'y') {
      await git.push();
      console.log('✅ Pushed to remote repository');
    } else {
      console.log('⏸️  Skipped push. Remember to push manually: git push');
    }
    rl.close();
    
  } catch (err) {
    console.error('\n⚠️  Git operation failed:', err.message);
    console.log('Please manually commit public.pem:');
    console.log('  git add public.pem .gitignore');
    console.log('  git commit -m "Add public key for signaling system"');
    console.log('  git push');
  }
  
  console.log('\n📝 Next steps:');
  console.log('   1. Keep private.pem secure on your VPS');
  console.log('   2. Set environment variable on VPS:');
  console.log('      export PRIVATE_KEY_PEM="$(cat private.pem)"');
  console.log('\n⚠️  WARNING: Never commit private.pem to version control!');
}

// Run the generator
generateKeypair().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
