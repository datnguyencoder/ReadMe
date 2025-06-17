# Luồng đi và mã nguồn cụ thể của các chức năng

## I. Chức năng đăng nhập (Login)

### Luồng đi:
1. Client gửi request đến endpoint `/api/auth/login`
2. `AuthenticationController` nhận request và chuyển đến `AuthenticationService`
3. `AuthenticationService` xác thực thông tin đăng nhập và tạo JWT tokens
4. Trả về `LoginResponse` chứa access token và refresh token

### Các class cụ thể:

1. **Controller:** `AuthenticationController`
```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authenticationService.login(request);
        return ResponseEntity.ok(response);
    }
}
```

2. **Service:** `AuthenticationService`
```java
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    
    public LoginResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        User user = (User) authentication.getPrincipal();

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        
        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
```

3. **JWT Service:** `JwtService`
```java
@Service
@RequiredArgsConstructor
public class JwtService {
    @Value("${jwt.secret-key}")
    private String secretKey;
    
    public String generateAccessToken(User user) {
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        List<String> authorityNames = authorities.stream()
                .map(GrantedAuthority::getAuthority())
                .toList();

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS384);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issueTime(new Date())
                .claim("authorities", authorityNames)
                .claim("email", user.getEmail())
                .claim("userId", user.getId())
                .expirationTime(new Date(Instant.now().plus(30, ChronoUnit.MINUTES).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .build();

        Payload payload = new Payload(claimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(header, payload);
        try {
            jwsObject.sign(new MACSigner(secretKey));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
```

4. **Cấu hình Security:** `SecurityConfig`
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtDecoder jwtDecoder;
    private final UserDetailServiceCustomizer userDetailsService;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> 
                auth.requestMatchers(WHITE_LIST).permitAll()
                    .requestMatchers(ADMIN_ENDPOINTS).hasAuthority("ROLE_ADMIN")
                    .requestMatchers(MANAGER_ENDPOINTS).hasAnyAuthority("ROLE_ADMIN", "ROLE_MANAGER")
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder)
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        return http.build();
    }
}
```

## II. Chức năng đăng ký (Register)

### Luồng đi:
1. Client gửi request đến endpoint `/api/auth/register`
2. `AuthenticationController` nhận request và chuyển đến `UserService`
3. `UserService` kiểm tra email/username, tạo người dùng mới và mã hóa mật khẩu
4. Gửi email chào mừng và trả về thông tin đăng ký

### Các class cụ thể:

1. **Controller:** `AuthenticationController`
```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final UserService userService;
    
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> createUser(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
```

2. **Service:** `UserService`
```java
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailServiceImpl mailService;
    
    public RegisterResponse createUser(RegisterRequest request) {
        // Kiểm tra email và username đã tồn tại chưa
        Optional<User> byEmail = userRepository.findByEmail(request.getEmail());
        Optional<User> byUsername = userRepository.findByUsername(request.getUsername());
        if(byEmail.isPresent()) {
            throw new RuntimeException("Email existed");
        }
        if (byUsername.isPresent()) {
            throw new RuntimeException("Username existed");
        }

        // Tạo user mới
        User user = User.builder()
                .username(request.getUsername())
                .fullname(request.getFullname())
                .gender(request.getGender())
                .yob(request.getYob())
                .email(request.getEmail())
                .avatar("https://freesvg.org/img/abstract-user-flat-3.png")
                .phone(request.getPhone())
                .address(request.getAddress())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(ERole.ROLE_MEMBER)
                .enabled(true)
                .build();

        userRepository.save(user);

        // Gửi email chào mừng
        try {
            mailService.sendWelcomeEmail(user.getEmail(), user.getFullname());
        } catch (MessagingException | UnsupportedEncodingException e) {
            log.error("SendEmail failed with email: {}", user.getEmail());
            throw new RuntimeException(e);
        }

        return RegisterResponse.builder()
                .username(user.getUsername())
                .fullname(user.getFullname())
                .email(user.getEmail())
                .phone(user.getPhone())
                .build();
    }
}
```

3. **Entity:** `User`
```java
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Inheritance(strategy = InheritanceType.JOINED)
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
    private String fullname;
    private String avatar;
    private String gender;
    private LocalDate yob;
    @Column(nullable = false)
    private String email;
    private String phone;
    private String address;

    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private ERole role;

    private boolean enabled = true;
    
    // UserDetails interface methods
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role.name()));
    }
}
```

## III. Chức năng quên mật khẩu (Forgot Password)

### Luồng đi:
1. Client gửi request đến `/api/auth/password/forgot` với email
2. `PasswordResetController` chuyển request đến `PasswordResetService`
3. `PasswordResetService` tạo OTP, lưu vào database và gửi email
4. Client gửi request xác nhận OTP và mật khẩu mới đến `/api/auth/password/reset`
5. `PasswordResetService` kiểm tra OTP và cập nhật mật khẩu mới

### Các class cụ thể:

1. **Controller:** `PasswordResetController`
```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth/password")
public class PasswordResetController {
    private final PasswordResetService passwordResetService;

    @PostMapping("/forgot")
    public ResponseEntity<ForgotPasswordResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        ForgotPasswordResponse response = passwordResetService.sendOtp(request);
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/reset")
    public ResponseEntity<ResetPasswordResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        ResetPasswordResponse response = passwordResetService.resetPassword(request);
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}
```

2. **Service:** `PasswordResetServiceImpl`
```java
@Service
@RequiredArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {
    private final UserRepository userRepository;
    private final PasswordResetOtpRepository otpRepository;
    private final EmailServiceImpl mailService;
    private final TemplateEngine templateEngine;
    private final PasswordEncoder passwordEncoder;
    
    @Override
    @Transactional
    public ForgotPasswordResponse sendOtp(ForgotPasswordRequest request) {
        // Kiểm tra email có tồn tại không
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy người dùng với email: " + request.getEmail()));
        
        // Tạo mã OTP ngẫu nhiên 4 chữ số
        String otp = generateOtp();
        
        // Lưu OTP vào database
        PasswordResetOtp passwordResetOtp = PasswordResetOtp.builder()
                .email(request.getEmail())
                .otp(otp)
                .used(false)
                .build();
        
        otpRepository.save(passwordResetOtp);
        
        // Gửi email chứa OTP
        try {
            sendOtpEmail(request.getEmail(), otp);
            return ForgotPasswordResponse.builder()
                    .success(true)
                    .message("Mã OTP đã được gửi đến email của bạn")
                    .build();
        } catch (Exception e) {
            return ForgotPasswordResponse.builder()
                    .success(false)
                    .message("Lỗi khi gửi OTP")
                    .build();
        }
    }

    @Override
    @Transactional
    public ResetPasswordResponse resetPassword(ResetPasswordRequest request) {
        // Kiểm tra email có tồn tại không
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy người dùng với email: " + request.getEmail()));
        
        // Kiểm tra OTP có hợp lệ không
        PasswordResetOtp passwordResetOtp = otpRepository.findByEmailAndOtpAndUsedFalse(request.getEmail(), request.getOtp())
                .orElseThrow(() -> new ResourceNotFoundException("Mã OTP không hợp lệ hoặc đã hết hạn"));
        
        // Kiểm tra OTP có hết hạn không
        if (passwordResetOtp.isExpired()) {
            return ResetPasswordResponse.builder()
                    .success(false)
                    .message("Mã OTP đã hết hạn, vui lòng yêu cầu mã mới")
                    .build();
        }
        
        // Cập nhật mật khẩu mới
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        
        // Đánh dấu OTP đã sử dụng
        passwordResetOtp.setUsed(true);
        otpRepository.save(passwordResetOtp);
        
        return ResetPasswordResponse.builder()
                .success(true)
                .message("Đặt lại mật khẩu thành công")
                .build();
    }
    
    private String generateOtp() {
        Random random = new Random();
        return String.format("%04d", random.nextInt(10000));
    }
    
    private void sendOtpEmail(String email, String otp) throws MessagingException, UnsupportedEncodingException {
        Context context = new Context();
        context.setVariable("otp", otp);
        String content = templateEngine.process("email/reset-password-otp", context);
        mailService.sendEmail(email, "Mã xác nhận đặt lại mật khẩu", content);
    }
}
```

3. **Entity:** `PasswordResetOtp`
```java
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "password_reset_otp")
public class PasswordResetOtp {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String email;
    private String otp;
    private LocalDateTime expiryTime;
    private boolean used;
    
    @PrePersist
    public void setExpiryTime() {
        // OTP hết hạn sau 5 phút
        this.expiryTime = LocalDateTime.now().plusMinutes(5);
    }
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryTime);
    }
}
```

## IV. Chức năng đặt lịch hẹn (Appointment)

### Luồng đi:
1. Client gửi request đến `/api/appointments`
2. `AppointmentController` nhận request và chuyển đến `AppointmentService`
3. `AppointmentService` tìm consultant có slot trống và tạo cuộc hẹn
4. Gửi email xác nhận và trả về thông tin cuộc hẹn

### Các class cụ thể:

1. **Controller:** `AppointmentController`
```java
@RestController
@RequestMapping("/api/appointments")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AppointmentController {
    private final AppointmentService appointmentService;

    @PostMapping
    public ResponseEntity<AppointmentResponseDto> createAppointment(@Valid @RequestBody AppointmentRequestDto requestDto) {
        AppointmentResponseDto responseDto = appointmentService.createAppointment(requestDto);
        return new ResponseEntity<>(responseDto, HttpStatus.CREATED);
    }
    
    @GetMapping("/guest")
    public ResponseEntity<List<AppointmentResponseDto>> getGuestAppointments(@RequestParam String email) {
        List<AppointmentResponseDto> appointments = appointmentService.getAppointmentsByGuestEmail(email);
        return ResponseEntity.ok(appointments);
    }
    
    @PostMapping("/{id}/cancel/guest")
    public ResponseEntity<AppointmentResponseDto> cancelGuestAppointment(
            @PathVariable Long id,
            @RequestParam String email) {
        AppointmentResponseDto canceledAppointment = appointmentService.cancelAppointmentByGuest(id, email);
        return ResponseEntity.ok(canceledAppointment);
    }
    
    // Các API khác cho người dùng đã đăng nhập và consultant
}
```

2. **Service:** `AppointmentServiceImpl`
```java
@Service
@RequiredArgsConstructor
public class AppointmentServiceImpl implements AppointmentService {
    private final AppointmentRepository appointmentRepository;
    private final ConsultantRepository consultantRepository;
    private final TopicRepository topicRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final SlotRepository slotRepository;
    private final Random random = new Random();

    @Override
    public AppointmentResponseDto createAppointment(AppointmentRequestDto requestDto) {
        // Lấy topic theo ID
        Topic topic = topicRepository.findById(requestDto.getTopicId())
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy chủ đề tư vấn với ID: " + requestDto.getTopicId()));

        // Tìm consultant phù hợp
        List<Consultant> availableConsultants = consultantRepository.findByEnabledTrue();
        
        if (availableConsultants.isEmpty()) {
            throw new ResourceNotFoundException("Không có tư vấn viên nào đang hoạt động");
        }
        
        // Tìm tất cả các consultant có slot phù hợp
        List<Consultant> consultantsWithMatchingSlots = new ArrayList<>();
        List<Slot> matchingSlots = new ArrayList<>();
        
        for (Consultant c : availableConsultants) {
            Optional<Slot> optionalSlot = slotRepository.findAvailableSlotByConsultantAndDateTime(
                    c.getId(),
                    requestDto.getAppointmentDate(),
                    requestDto.getAppointmentTime());
            
            if (optionalSlot.isPresent()) {
                consultantsWithMatchingSlots.add(c);
                matchingSlots.add(optionalSlot.get());
            }
        }
        
        // Chọn ngẫu nhiên một consultant có slot phù hợp
        Consultant consultant;
        Slot matchedSlot;
        
        if (!consultantsWithMatchingSlots.isEmpty()) {
            int randomIndex = random.nextInt(consultantsWithMatchingSlots.size());
            consultant = consultantsWithMatchingSlots.get(randomIndex);
            matchedSlot = matchingSlots.get(randomIndex);
        } else {
            throw new ResourceNotFoundException("Không có tư vấn viên nào rảnh vào thời điểm này");
        }

        // Khởi tạo đối tượng Appointment
        Appointment appointment = new Appointment();
        appointment.setCustomerName(requestDto.getCustomerName());
        appointment.setPhoneNumber(requestDto.getPhoneNumber());
        appointment.setEmail(requestDto.getEmail());
        appointment.setAppointmentDate(requestDto.getAppointmentDate());
        appointment.setAppointmentTime(requestDto.getAppointmentTime());
        appointment.setTopic(topic);
        appointment.setConsultant(consultant);
        appointment.setStatus("PENDING");

        // Nếu có userId, đây là thành viên đã đăng nhập
        if (requestDto.getUserId() != null) {
            User user = userRepository.findById(requestDto.getUserId())
                    .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy người dùng với ID: " + requestDto.getUserId()));
            appointment.setUser(user);
            appointment.setGuest(false);
        } else {
            // Nếu không có userId, đây là khách
            appointment.setGuest(true);
        }

        // Cập nhật trạng thái slot
        matchedSlot.setAvailable(false);
        slotRepository.save(matchedSlot);

        // Lưu vào database
        Appointment savedAppointment = appointmentRepository.save(appointment);

        // Gửi email xác nhận đặt lịch
        emailService.sendAppointmentConfirmation(savedAppointment);

        // Chuyển đổi thành AppointmentResponseDto và trả về
        return mapToResponseDto(savedAppointment);
    }
    
    // Các phương thức khác cho quản lý cuộc hẹn
}
```

3. **Entity:** `Appointment`
```java
@Entity
@Table(name = "appointments")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Appointment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "customer_name", nullable = false)
    private String customerName;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "appointment_date", nullable = false)
    private LocalDate appointmentDate;

    @Column(name = "appointment_time", nullable = false)
    private LocalTime appointmentTime;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "topic_id", nullable = false)
    private Topic topic;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "consultant_id", nullable = false)
    private Consultant consultant;

    @Column(name = "is_guest", nullable = false)
    private boolean isGuest = true;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "status")
    private String status = "PENDING"; // PENDING, CONFIRMED, CANCELED, COMPLETED
}
```

4. **Email Service:** `EmailServiceImpl`
```java
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    
    @Override
    public void sendAppointmentConfirmation(Appointment appointment) {
        try {
            String subject = "Xác nhận đặt lịch tư vấn thành công";
            
            Context context = new Context();
            context.setVariable("appointment", appointment);
            
            String content = templateEngine.process("email/appointment-confirmation", context);
            
            sendEmail(appointment.getEmail(), subject, content);
        } catch (Exception e) {
            log.error("Lỗi khi gửi email xác nhận đặt lịch: {}", e.getMessage());
        }
    }
    
    @Override
    public void sendEmail(String to, String subject, String content) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setFrom("dupss.system312@gmail.com", "DUPSS Support Team");
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(content, true);
        
        mailSender.send(message);
    }
}
```

## V. Chức năng quản lý slot (Slot Management)

### Luồng đi:
1. Consultant gửi request tạo slot đến `/api/slots`
2. `SlotController` chuyển request đến `SlotService`
3. `SlotService` kiểm tra tính hợp lệ và tạo slot mới
4. Slot sẵn sàng được đặt lịch

### Các class cụ thể:

1. **Controller:** `SlotController`
```java
@RestController
@RequestMapping("/api/slots")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class SlotController {
    private final SlotService slotService;

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_CONSULTANT')")
    public ResponseEntity<SlotResponseDto> createSlot(@Valid @RequestBody SlotRequestDto requestDto) {
        SlotResponseDto responseDto = slotService.createSlot(requestDto);
        return new ResponseEntity<>(responseDto, HttpStatus.CREATED);
    }
    
    @PostMapping("/batch")
    @PreAuthorize("hasAuthority('ROLE_CONSULTANT')")
    public ResponseEntity<List<SlotResponseDto>> createMultipleSlots(@Valid @RequestBody List<SlotRequestDto> requestDtos) {
        List<SlotResponseDto> responseDtos = slotService.createMultipleSlots(requestDtos);
        return new ResponseEntity<>(responseDtos, HttpStatus.CREATED);
    }
    
    @PostMapping("/schedule")
    @PreAuthorize("hasAuthority('ROLE_CONSULTANT')")
    public ResponseEntity<List<SlotResponseDto>> createSlotsFromSchedule(@Valid @RequestBody BatchSlotRequestDto batchRequest) {
        List<SlotResponseDto> responseDtos = slotService.createSlotsFromSchedule(batchRequest);
        return new ResponseEntity<>(responseDtos, HttpStatus.CREATED);
    }
    
    @GetMapping("/available")
    public ResponseEntity<List<SlotResponseDto>> getAvailableSlots(
            @RequestParam Long consultantId,
            @RequestParam @DateTimeFormat(pattern = "dd/MM/yyyy") LocalDate date) {
        List<Slot> availableSlots = slotService.getAvailableSlotsByConsultantAndDate(consultantId, date);
        List<SlotResponseDto> responseDtos = availableSlots.stream()
                .map(this::mapToResponseDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(responseDtos);
    }
    
    // Các API khác cho quản lý slot
}
```

2. **Service:** `SlotServiceImpl`
```java
@Service
@RequiredArgsConstructor
public class SlotServiceImpl implements SlotService {
    private final SlotRepository slotRepository;
    private final ConsultantRepository consultantRepository;

    @Override
    public SlotResponseDto createSlot(SlotRequestDto requestDto) {
        Consultant consultant = consultantRepository.findById(requestDto.getConsultantId())
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy tư vấn viên với ID: " + requestDto.getConsultantId()));

        // Kiểm tra tính hợp lệ của thời gian
        validateTimeRange(requestDto.getStartTime(), requestDto.getEndTime());
        
        // Kiểm tra chồng chéo thời gian
        checkTimeOverlap(consultant, requestDto.getDate(), requestDto.getStartTime(), requestDto.getEndTime());

        // Tạo đối tượng Slot từ requestDto
        Slot slot = new Slot();
        slot.setDate(requestDto.getDate());
        slot.setStartTime(requestDto.getStartTime());
        slot.setEndTime(requestDto.getEndTime());
        slot.setConsultant(consultant);
        slot.setAvailable(requestDto.isAvailable());

        Slot savedSlot = slotRepository.save(slot);
        return mapToResponseDto(savedSlot);
    }
    
    @Override
    public List<SlotResponseDto> createSlotsFromSchedule(BatchSlotRequestDto batchRequest) {
        // Kiểm tra tính hợp lệ của khoảng thời gian
        if (batchRequest.getStartDate().isAfter(batchRequest.getEndDate())) {
            throw new IllegalArgumentException("Ngày bắt đầu phải trước hoặc bằng ngày kết thúc");
        }
        
        // Kiểm tra tính hợp lệ của thời gian
        validateTimeRange(batchRequest.getStartTime(), batchRequest.getEndTime());
        
        // Tạo danh sách ngày trong khoảng thời gian
        List<LocalDate> allDates = generateDateRange(batchRequest.getStartDate(), batchRequest.getEndDate());
        
        // Lọc ra các ngày đúng với các ngày trong tuần được chọn
        List<LocalDate> selectedDates = allDates.stream()
                .filter(date -> {
                    int dayOfWeekValue = date.getDayOfWeek().getValue(); // 1 (Thứ 2) đến 7 (Chủ nhật)
                    return batchRequest.getDaysOfWeek().contains(dayOfWeekValue);
                })
                .collect(Collectors.toList());
        
        // Tạo các SlotRequestDto từ các ngày đã chọn
        List<SlotRequestDto> slotRequests = selectedDates.stream()
                .map(date -> {
                    SlotRequestDto requestDto = new SlotRequestDto();
                    requestDto.setDate(date);
                    requestDto.setStartTime(batchRequest.getStartTime());
                    requestDto.setEndTime(batchRequest.getEndTime());
                    requestDto.setConsultantId(batchRequest.getConsultantId());
                    requestDto.setAvailable(batchRequest.isAvailable());
                    return requestDto;
                })
                .collect(Collectors.toList());
        
        // Gọi phương thức createMultipleSlots để tạo các slot
        return createMultipleSlots(slotRequests);
    }
    
    // Các phương thức hỗ trợ khác
    private void validateTimeRange(LocalTime startTime, LocalTime endTime) {
        if (startTime.isAfter(endTime) || startTime.equals(endTime)) {
            throw new IllegalArgumentException("Thời gian bắt đầu phải trước thời gian kết thúc");
        }
    }
    
    private void checkTimeOverlap(Consultant consultant, LocalDate date, LocalTime startTime, LocalTime endTime) {
        List<Slot> existingSlots = slotRepository.findByConsultantAndDate(consultant, date);
        
        for (


# Phân tích luồng và Security của hệ thống

## I. Luồng đăng nhập (Login)
Search files...
Search files...
Search files...
Search files...
Read file: src/main/java/com/dupss/app/BE_Dupss/dto/request/AppointmentRequestDto.java
Read file: src/main/java/com/dupss/app/BE_Dupss/config/SecurityConfig.java
Sau khi phân tích toàn bộ mã nguồn, tôi sẽ trình bày chi tiết về luồng và security của hệ thống:

# Phân tích luồng và Security của hệ thống

## I. Tổng quan về Security

Hệ thống sử dụng JWT (JSON Web Token) để xác thực và phân quyền, với các điểm chính:

1. **Cơ chế xác thực**: 
   - Stateless authentication: Không lưu trữ phiên trên server
   - JWT đóng vai trò là bearer token
   - Sử dụng thuật toán HS384 để ký token

2. **Cấu trúc JWT**:
   - `Header`: Chứa thuật toán ký (HS384)
   - `Payload`: Chứa thông tin người dùng (username, userId, email, quyền)
   - `Signature`: Được tạo bằng secret key lưu trữ tại server

3. **Quản lý phiên**:
   - Access token có thời hạn 30 phút
   - Refresh token dùng để cấp lại access token mới

4. **Phân quyền**:
   - Hệ thống có các vai trò: ADMIN, MANAGER, CONSULTANT, MEMBER
   - Sử dụng annotation `@PreAuthorize` để kiểm soát quyền truy cập API

5. **Danh sách API công khai**:
   ```java
   private static final String[] WHITE_LIST = {
       "/api/auth/**",
       "/api/public/**",
       "/swagger-ui/**",
       "/v3/api-docs/**",
       "/swagger-ui.html",
       "/api/appointments",
       "/api/appointments/guest",
       "/api/appointments/*/cancel/guest",
       "/api/slots/available",
       "/api/topics",
       "/api/consultants",
       "/api/consultants/topic/**"
   };
   ```

## II. Luồng đăng nhập (Login)

1. **Client gửi request đăng nhập**:
   ```http
   POST /api/auth/login
   {
     "username": "user123",
     "password": "password123"
   }
   ```

2. **Server xử lý**:
   - `AuthenticationManager` xác thực thông tin đăng nhập
   - `UserDetailServiceCustomizer` tìm kiếm người dùng trong database
   - `PasswordEncoder` (BCrypt) kiểm tra mật khẩu
   - Nếu đúng, tạo và trả về tokens:
     ```java
     LoginResponse.builder()
        .accessToken(accessToken)
        .refreshToken(refreshToken)
        .build();
     ```

3. **Lưu trữ token**:
   - Client lưu tokens vào localStorage/cookie
   - Access token được gửi kèm trong header của các request sau đó

4. **Kiểm tra token**:
   - Server sử dụng `JwtDecoderCustomizer` để xác thực và giải mã token
   - Token không hợp lệ hoặc hết hạn sẽ trả về lỗi 401

## III. Luồng đăng ký (Register)

1. **Client gửi request đăng ký**:
   ```http
   POST /api/auth/register
   {
     "username": "newuser",
     "password": "newpassword",
     "fullname": "Người dùng mới",
     "gender": "Nam",
     "email": "newuser@example.com",
     "phone": "0987654321",
     "address": "Hà Nội"
   }
   ```

2. **Server xử lý**:
   - Kiểm tra tài khoản và email có tồn tại không
   - Mã hóa mật khẩu với BCrypt
   - Tạo người dùng mới với vai trò ROLE_MEMBER
   - Lưu vào database

3. **Gửi email chào mừng**:
   - Hệ thống gửi email chào mừng đến email đăng ký
   - Sử dụng template HTML và Thymeleaf

4. **Trả về thông tin**:
   ```java
   RegisterResponse.builder()
      .username(user.getUsername())
      .fullname(user.getFullname())
      .email(user.getEmail())
      .phone(user.getPhone())
      .build();
   ```

## IV. Luồng quên mật khẩu (Forgot Password)

1. **Yêu cầu đặt lại mật khẩu**:
   ```http
   POST /api/auth/password/forgot
   {
     "email": "user@example.com"
   }
   ```

2. **Tạo và gửi OTP**:
   - Hệ thống tạo mã OTP ngẫu nhiên 4 chữ số
   - Lưu OTP vào database với thời hạn 5 phút
   - Gửi OTP qua email sử dụng template HTML

3. **Xác thực OTP và đặt lại mật khẩu**:
   ```http
   POST /api/auth/password/reset
   {
     "email": "user@example.com",
     "otp": "1234",
     "newPassword": "newpassword"
   }
   ```

4. **Xử lý đặt lại mật khẩu**:
   - Kiểm tra OTP có hợp lệ không (đúng, chưa sử dụng, chưa hết hạn)
   - Mã hóa mật khẩu mới và cập nhật vào database
   - Đánh dấu OTP đã sử dụng

## V. Luồng đặt lịch hẹn (Appointment)

### A. Quy trình đặt lịch:

1. **Khách hàng tạo yêu cầu đặt lịch**:
   ```http
   POST /api/appointments
   {
     "customerName": "Nguyễn Văn A",
     "phoneNumber": "0987654321",
     "email": "nguyenvana@example.com",
     "appointmentDate": "15/06/2023",
     "appointmentTime": "09:00",
     "topicId": 1,
     "userId": null  // có thể null nếu là khách vãng lai
   }
   ```

2. **Server xử lý yêu cầu**:
   - Lấy thông tin topic từ topicId
   - Tìm danh sách consultant đang hoạt động
   - Tìm các consultant có slot trống vào thời điểm yêu cầu
   - Chọn ngẫu nhiên một consultant có slot phù hợp (sau khi update)

3. **Cập nhật trạng thái và thông báo**:
   - Tạo cuộc hẹn với trạng thái PENDING
   - Đánh dấu slot đã chọn là không khả dụng
   - Lưu thông tin cuộc hẹn vào database
   - Gửi email xác nhận đến khách hàng

### B. Security trong đặt lịch:

1. **Người dùng chưa đăng nhập**:
   - Có thể đặt lịch thông qua API công khai `/api/appointments`
   - Được phép hủy cuộc hẹn thông qua email và ID cuộc hẹn
   - Xem lịch sử cuộc hẹn thông qua email

2. **Người dùng đã đăng nhập**:
   - Thông tin cá nhân được điền tự động từ tài khoản
   - Hủy cuộc hẹn thông qua API được xác thực
   - Xem lịch sử cuộc hẹn thông qua tài khoản

3. **Consultant**:
   - Quản lý slot thời gian (tạo, cập nhật, xóa)
   - Xem và cập nhật trạng thái cuộc hẹn
   - Chỉ thấy và quản lý được cuộc hẹn của chính mình

4. **Admin**:
   - Xem tất cả cuộc hẹn trong hệ thống
   - Quản lý tài khoản người dùng và consultant

## VI. Các biện pháp bảo mật bổ sung

1. **CORS Protection**:
   - Cấu hình CORS cho phép các origin, method cụ thể
   - Bảo vệ khỏi CSRF và các tấn công cross-origin

2. **Password Policy**:
   - Mật khẩu được mã hóa bằng BCrypt
   - Yêu cầu mật khẩu tối thiểu 6 ký tự

3. **Input Validation**:
   - Sử dụng Jakarta Bean Validation cho validation đầu vào
   - Kiểm tra format email, số điện thoại, ngày giờ

4. **Exception Handling**:
   - `GlobalExceptionHandler` xử lý các ngoại lệ
   - Trả về thông báo lỗi phù hợp

5. **Authorization Checks**:
   - Kiểm tra quyền sở hữu trước khi thao tác với dữ liệu
   - Ví dụ: consultant chỉ cập nhật được slot/cuộc hẹn của chính mình

## VII. Kết luận

Hệ thống quản lý đặt lịch hẹn sử dụng kiến trúc bảo mật hiện đại với JWT, cơ chế xác thực stateless, và phân quyền chi tiết. Việc xác thực và phân quyền được thực hiện ở nhiều lớp, từ security filters đến method-level security, đảm bảo dữ liệu được bảo vệ khỏi truy cập trái phép. Các luồng nghiệp vụ được thiết kế rõ ràng, dễ sử dụng cho cả người dùng đã đăng nhập và khách vãng lai.
