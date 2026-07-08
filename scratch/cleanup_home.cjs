const fs = require('fs');
const path = 'c:/Users/Piyush/Desktop/AI-VAPT-main/AI-VAPT-main/src/components/home.tsx';
let content = fs.readFileSync(path, 'utf8');
const lines = content.split('\n');

const startIndex = lines.findIndex(l => l.includes('// Calculate risk scores based on professional methodology')) - 1;
const endIndex = lines.findIndex(l => l.includes('const generateTacticalReconnaissance =')) - 1;

if (startIndex !== -1 && endIndex !== -1 && startIndex < endIndex) {
    console.log(`Deleting from line ${startIndex + 1} to ${endIndex + 1}`);
    lines.splice(startIndex, endIndex - startIndex);
    fs.writeFileSync(path, lines.join('\n'));
    console.log('Successfully cleaned home.tsx');
} else {
    console.log('Could not find markers', { startIndex, endIndex });
}
