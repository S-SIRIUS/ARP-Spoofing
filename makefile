# 라이브러리와 컴파일 플래그 설정
LDLIBS = -lpcap
CXXFLAGS = -Iinclude  # include 디렉토리를 헤더 파일 경로로 추가

# 소스 및 객체 파일 경로 설정
SRC_DIR = src         # 소스 파일이 있는 디렉토리
OBJ_DIR = obj         # 객체 파일을 저장할 디렉토리
INCLUDE_DIR = include # 헤더 파일이 있는 디렉토리

# 소스 파일 목록
SOURCES = $(SRC_DIR)/utils.cpp $(SRC_DIR)/extract.cpp $(SRC_DIR)/mac.cpp \
          $(SRC_DIR)/ip.cpp $(SRC_DIR)/attack.cpp $(SRC_DIR)/main.cpp

# 객체 파일 목록
OBJECTS = $(SRC_DIR)/utils.o $(SRC_DIR)/extract.o $(SRC_DIR)/mac.o \
          $(SRC_DIR)/ip.o $(SRC_DIR)/attack.o $(SRC_DIR)/main.o

# 최종 실행 파일 이름
TARGET = arp-spoof

# 기본 빌드 규칙
all: $(TARGET)

# 객체 파일 빌드 규칙
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 최종 실행 파일 빌드 규칙
$(TARGET): $(OBJECTS)
	$(CXX) $^ $(LDLIBS) -o $@

# 클린 규칙
clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET)

