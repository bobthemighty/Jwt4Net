using System;

namespace Jwt4Net.Claims
{
    public struct UnixTimeStamp : IEquatable<UnixTimeStamp>
    {
        private readonly long _seconds;
        private static readonly DateTime _epoch = new DateTime(1970, 1, 1);

        public UnixTimeStamp(long seconds)
        {
            _seconds = seconds;
        }

        public UnixTimeStamp(DateTime dateTime)
        {
            _seconds = (long)dateTime.Subtract(_epoch).TotalSeconds;
        }

        public long Value
        {
            get { return _seconds; }
        }

        public DateTime ToDateTime()
        {
            return Epoch.AddSeconds(_seconds);
        }

        public static DateTime Epoch
        {
            get { return _epoch; }
        }

        public bool Equals(UnixTimeStamp other)
        {
            return other._seconds == _seconds;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (obj.GetType() != typeof (UnixTimeStamp)) return false;
            return Equals((UnixTimeStamp) obj);
        }

        public override int GetHashCode()
        {
            return _seconds.GetHashCode();
        }

        public static bool operator ==(UnixTimeStamp left, UnixTimeStamp right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(UnixTimeStamp left, UnixTimeStamp right)
        {
            return !left.Equals(right);
        }
    }
}