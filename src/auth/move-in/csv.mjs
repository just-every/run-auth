// RFC 4180 reader: quoted fields may hold commas, line breaks and doubled quotes.
// Returns an array of records (arrays of strings); blank lines are dropped.
// A record wider than maxFields stops the read before it is kept.
export function readCsv(text,maxRecords,maxFields=Infinity) {
 const records=[];let record=[],field='',quoted=false,touched=false;
 const endField=()=>{record.push(field);field='';touched=false;if(record.length>maxFields)throw new RangeError('too_many_columns');};
 const endRecord=()=>{endField();if(record.length>1||record[0]!=='')records.push(record);record=[];if(records.length>maxRecords)throw new RangeError('too_many_rows');};
 for(let i=0;i<text.length;i++) {
  const c=text[i];
  if(quoted) {
   if(c==='"'&&text[i+1]==='"'){field+='"';i++;}
   else if(c==='"')quoted=false;
   else field+=c;
   continue;
  }
  if(c==='"'&&!touched){quoted=true;touched=true;}
  else if(c===',')endField();
  else if(c==='\n'||c==='\r'){if(c==='\r'&&text[i+1]==='\n')i++;endRecord();}
  else {field+=c;touched=true;}
 }
 if(quoted)throw new SyntaxError('unterminated_quote');
 if(field!==''||record.length)endRecord();
 return records;
}
