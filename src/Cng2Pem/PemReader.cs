using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Penge
{
    public class PemReader : IEnumerable<PemObject>
    {
        private readonly Stream _data;
        private bool _isRead = false;
        private List<PemObject> _pemData = new List<PemObject>();
        int currentLine;

        public static PemReader Create(Stream utf8StringEncoding)
        {
            throw new NotImplementedException();
        }


        public PemReader(Stream stream)
        {
            _data = stream;
        }

        public IEnumerator<PemObject> GetEnumerator()
        {
            if(!_isRead)
                Read();
            return _pemData.GetEnumerator();
        }

        private void Read()
        {
            var sr = new StreamReader(_data);
            var stringData = sr.ReadToEnd().Trim();
            var lines = stringData.Split('\n');
            
            currentLine = 0;
            while (currentLine < lines.Length)
            {
                var header = ExpectBeginHeader(lines);
                var body = ExpectPayload(lines);
                ExpectEnd(header, lines);
                _pemData.Add(new PemObject(header, body));
            }
            _isRead = true;
        }

        private string ExpectBeginHeader(string[] lines)
        {
            return ExpectHeader(lines, currentLine++, "BEGIN");
        }

        private byte[] ExpectPayload(string[] lines)
        {
            var dataLines = lines.Skip(currentLine).TakeWhile(l => l.StartsWith("-----") == false);
            if(dataLines.Count() == 0)
                throw new InvalidPemDocumentException("Expected payload at line "+currentLine+" but was empty");
            currentLine += dataLines.Count();
            return Convert.FromBase64String(string.Join(string.Empty, dataLines.ToArray()));
        }

        private void ExpectEnd(string header, string[] lines)
        {
            var end = ExpectHeader(lines, currentLine++, "END");
            if(end != header)
                throw new InvalidPemDocumentException("Invalid document, expected END "+header+" at line "+currentLine+" but was "+lines[currentLine]);
        }


        private string ExpectHeader(string[] lines, int currentLine)
        {
            if(lines.Length <= currentLine)
                throw new InvalidPemDocumentException("Expected header at line " + currentLine + " but was empty");

            var s = lines[currentLine];
            var i = 0;

            
            while(i<5)
            {
                var c = s[i++];
                if (c != '-')
                    throw new InvalidPemDocumentException("Invalid header at line " + currentLine + " expected '-' at position "+i+" but was " + c);
            }

            return new string(s.Skip(5).TakeWhile(c => c != '-').ToArray());
        }

        private string ExpectHeader(string[] lines, int currentLine, string tag)
        {
            if(false == tag.EndsWith(" "))
                tag = tag + " ";
            if (lines.Length <= currentLine)
                throw new InvalidPemDocumentException("Expected header at line " + currentLine + " but was empty");

            var s = lines[currentLine];
            var i = 0;


            while (i < 5)
            {
                var c = s[i++];
                if (c != '-')
                    throw new InvalidPemDocumentException("Invalid header at line " + currentLine + " expected '-' at position " + i + " but was " + c);
            }

            var header = new string(s.Skip(5).TakeWhile(c => c != '-').ToArray());
            if(false == header.StartsWith(tag))
            {
                throw new InvalidPemDocumentException("Unexpected header. Expected "+tag+" but was "+header);
            }
            return header.Replace(tag, "");
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}