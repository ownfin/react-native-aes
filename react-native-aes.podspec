
Pod::Spec.new do |s|
  s.name          = 'react-native-aes'
  s.version       = '1.3.10'
  s.summary       = 'Native module for AES encryption'
  s.author        = "ownfin"
  s.license       = 'MIT'
  s.requires_arc  = true
  s.homepage      = "https://github.com/ownfin/react-native-aes"
  s.source        = { :git => 'https://github.com/ownfin/react-native-aes' }
  s.platform      = :ios, '9.0'
  s.source_files  = "ios/**/*.{h,m}"

  s.dependency "React-Core"
end
