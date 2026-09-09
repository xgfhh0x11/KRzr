/*
 * Kernel-Level Race Condition Fuzzing Engine - Header File
 * 
 * Header for the Windows kernel-mode race condition fuzzing driver.
 * All modules are implemented in kernel_fuzzer.c.
 */

#ifndef KERNEL_FUZZER_H
#define KERNEL_FUZZER_H

#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntifs.h>
#include <windef.h>

// Driver version
#define KERNEL_FUZZER_VERSION_MAJOR 1
#define KERNEL_FUZZER_VERSION_MINOR 0
#define KERNEL_FUZZER_VERSION_BUILD 0

// IOCTL codes
#define KERNEL_FUZZER_DEVICE_TYPE 0x8000
#define IOCTL_START_FUZZING \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_FUZZING \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATUS \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_THREAD \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_MUTEX \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOCATE_MEMORY \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_MEMORY \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SIMULATE_RACE \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_COVERAGE \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_FAULT_PATTERNS \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Constants
#define RACE_FUZZER_TAG 'FZAR'
#define MAX_THREADS 64
#define MAX_RESOURCES 256
#define MAX_RACES 1024
#define MAX_COVERAGE_POINTS 10000
#define MAX_FAULT_PATTERNS 512
#define MAX_MUTATIONS 1000
#define MAX_INPUT_SIZE 1024
#define MAX_FUNCTION_NAME 64
#define MAX_DESCRIPTION 256
#define MAX_TRIGGER_CONDITION 128

// Enums
typedef enum _THREAD_STATE {
    THREAD_CREATED = 0,
    THREAD_RUNNING = 1,
    THREAD_WAITING = 2,
    THREAD_TERMINATED = 3
} THREAD_STATE;

typedef enum _RESOURCE_TYPE {
    RESOURCE_KERNEL_POOL = 0,
    RESOURCE_FILE_HANDLE = 1,
    RESOURCE_REGISTRY_KEY = 2,
    RESOURCE_NAMED_PIPE = 3,
    RESOURCE_SECTION_OBJECT = 4,
    RESOURCE_MUTEX = 5,
    RESOURCE_EVENT = 6,
    RESOURCE_SEMAPHORE = 7
} RESOURCE_TYPE;

typedef enum _ACCESS_TYPE {
    ACCESS_READ = 0,
    ACCESS_WRITE = 1,
    ACCESS_EXECUTE = 2,
    ACCESS_FREE = 3,
    ACCESS_ALLOCATE = 4
} ACCESS_TYPE;

typedef enum _CORRUPTION_TYPE {
    CORRUPTION_BUFFER_OVERFLOW = 0,
    CORRUPTION_USE_AFTER_FREE = 1,
    CORRUPTION_DOUBLE_FREE = 2,
    CORRUPTION_NULL_POINTER_DEREF = 3,
    CORRUPTION_UNINITIALIZED_MEMORY = 4,
    CORRUPTION_INTEGER_OVERFLOW = 5,
    CORRUPTION_RACE_CONDITION = 6
} CORRUPTION_TYPE;

typedef enum _FAULT_PATTERN_TYPE {
    FAULT_PATTERN_USE_AFTER_FREE = 0,
    FAULT_PATTERN_DOUBLE_FREE = 1,
    FAULT_PATTERN_HEAP_SPRAY = 2,
    FAULT_PATTERN_ROP_CHAIN = 3,
    FAULT_PATTERN_PRIVILEGE_ESCALATION = 4,
    FAULT_PATTERN_CODE_INJECTION = 5
} FAULT_PATTERN_TYPE;

typedef enum _MUTATION_TYPE {
    MUTATION_BIT_FLIP = 0,
    MUTATION_BYTE_FLIP = 1,
    MUTATION_ARITHMETIC = 2,
    MUTATION_INTERESTING = 3,
    MUTATION_HAVOC = 4,
    MUTATION_SPLICE = 5
} MUTATION_TYPE;

typedef enum _RACE_PATTERN {
    RACE_DOUBLE_LOCK = 0,
    RACE_LOCK_BYPASS = 1,
    RACE_USE_AFTER_FREE = 2,
    RACE_DOUBLE_FREE = 3,
    RACE_TOCTOU = 4,
    RACE_CONCURRENT_ACCESS = 5,
    RACE_RESOURCE_EXHAUSTION = 6,
    RACE_HANDLE_REUSE = 7
} RACE_PATTERN;

// Structures
typedef struct _FUZZING_CONFIG {
    ULONG MaxIterations;
    ULONG MaxThreads;
    ULONG MaxResources;
    ULONG TimeoutMs;
    ULONG CrashThreshold;
    ULONG PatternThreshold;
    BOOLEAN EnableCoverage;
    BOOLEAN EnableFaultPatterns;
} FUZZING_CONFIG, *PFUZZING_CONFIG;

typedef struct _THREAD_CONTEXT {
    LIST_ENTRY ListEntry;
    HANDLE ThreadHandle;
    PVOID StartRoutine;
    PVOID Parameter;
    ULONG ThreadId;
    THREAD_STATE State;
    KIRQL Irql;
    ULONG Priority;
    KAFFINITY Affinity;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastActivity;
    ULONG AccessCount;
    BOOLEAN LockHeld;
    ULONG LockCount;
    ULONG TaintLevel;
    CHAR Name[MAX_FUNCTION_NAME];
} THREAD_CONTEXT, *PTHREAD_CONTEXT;

typedef struct _RESOURCE_CONTEXT {
    LIST_ENTRY ListEntry;
    ULONG ResourceId;
    RESOURCE_TYPE ResourceType;
    PVOID Handle;
    ULONG AccessCount;
    LARGE_INTEGER LastAccess;
    BOOLEAN LockHeld;
    BOOLEAN CorruptionDetected;
    ULONG TaintLevel;
    ULONG Size;
    ULONG Tag;
    CHAR Name[MAX_FUNCTION_NAME];
    PVOID Data;
    ULONG Metadata[8];
} RESOURCE_CONTEXT, *PRESOURCE_CONTEXT;

typedef struct _RACE_CONDITION {
    LIST_ENTRY ListEntry;
    ULONG RaceId;
    CORRUPTION_TYPE CorruptionType;
    PVOID MemoryAddress;
    ULONG ThreadCount;
    ULONG ThreadIds[MAX_THREADS];
    LARGE_INTEGER DetectionTime;
    ULONG Severity;
    BOOLEAN PatternPotential;
    CHAR Description[MAX_DESCRIPTION];
    ULONG Metadata[4];
} RACE_CONDITION, *PRACE_CONDITION;

typedef struct _COVERAGE_POINT {
    LIST_ENTRY ListEntry;
    PVOID Address;
    CHAR FunctionName[MAX_FUNCTION_NAME];
    ULONG HitCount;
    LARGE_INTEGER FirstHit;
    LARGE_INTEGER LastHit;
    ULONG ThreadIds[MAX_THREADS];
    ULONG ThreadCount;
    BOOLEAN IsHit;
    ULONG TaintLevel;
    ULONG Metadata[4];
} COVERAGE_POINT, *PCOVERAGE_POINT;

typedef struct _FAULT_PATTERN {
    LIST_ENTRY ListEntry;
    ULONG PayloadId;
    FAULT_PATTERN_TYPE PatternType;
    ULONG Complexity;
    ULONG SuccessProbability;
    PVOID PayloadData;
    ULONG DataSize;
    PVOID TargetAddress;
    CHAR TriggerCondition[MAX_TRIGGER_CONDITION];
    ULONG Metadata[16];
} FAULT_PATTERN, *PFAULT_PATTERN;

typedef struct _MUTATION_RESULT {
    LIST_ENTRY ListEntry;
    ULONG MutationId;
    MUTATION_TYPE MutationType;
    PVOID OriginalInput;
    PVOID MutatedInput;
    ULONG InputSize;
    ULONG CoverageGained;
    ULONG NewPaths;
    BOOLEAN CrashInduced;
    BOOLEAN PatternFound;
    ULONG Metadata[8];
} MUTATION_RESULT, *PMUTATION_RESULT;

typedef struct _FUZZING_STATUS {
    BOOLEAN IsRunning;
    ULONG IterationsCompleted;
    ULONG CrashesFound;
    ULONG PatternsFound;
    ULONG RaceConditionsDetected;
    ULONG CoveragePercentage;
    ULONG UniquePaths;
    ULONG TotalThreadsCreated;
    ULONG TotalResourcesCreated;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    ULONG TotalCoveragePoints;
    ULONG HitCoveragePoints;
    ULONG TotalPatterns;
    ULONG HighConfidencePatterns;
} FUZZING_STATUS, *PFUZZING_STATUS;

typedef struct _INPUT_DATA {
    LIST_ENTRY ListEntry;
    PVOID Data;
    ULONG Size;
    ULONG Priority;
    ULONG HitCount;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastUsed;
    BOOLEAN IsInteresting;
    ULONG Metadata[4];
} INPUT_DATA, *PINPUT_DATA;

// Global variables (extern declarations)
extern PDEVICE_OBJECT g_DeviceObject;
extern PUNICODE_STRING g_DeviceName;
extern PUNICODE_STRING g_SymbolicLinkName;
extern BOOLEAN g_FuzzingActive;
extern KSPIN_LOCK g_GlobalLock;
extern KSPIN_LOCK g_FuzzingLock;
extern KSPIN_LOCK g_ThreadLock;
extern KSPIN_LOCK g_ResourceLock;
extern KSPIN_LOCK g_RaceLock;
extern KSPIN_LOCK g_CoverageLock;
extern KSPIN_LOCK g_PatternLock;
extern KSPIN_LOCK g_MutationLock;
extern KSPIN_LOCK g_InputLock;

extern LIST_ENTRY g_ThreadList;
extern LIST_ENTRY g_ResourceList;
extern LIST_ENTRY g_RaceList;
extern LIST_ENTRY g_CoverageList;
extern LIST_ENTRY g_PatternList;
extern LIST_ENTRY g_MutationList;
extern LIST_ENTRY g_InputList;

extern ULONG g_ThreadCounter;
extern ULONG g_ResourceCounter;
extern ULONG g_RaceCounter;
extern ULONG g_CoverageCounter;
extern ULONG g_PatternCounter;
extern ULONG g_MutationCounter;
extern ULONG g_InputCounter;

extern FUZZING_CONFIG g_FuzzingConfig;
extern FUZZING_STATUS g_FuzzingStatus;

// Function prototypes

// Driver entry points
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Main fuzzing functions
NTSTATUS StartFuzzing(PFUZZING_CONFIG Config);
VOID StopFuzzing(VOID);
NTSTATUS GetFuzzingStatus(PFUZZING_STATUS Status);
VOID FuzzingLoop(PVOID Parameter);
VOID FuzzingIteration(ULONG Iteration);

// Module 1: Thread Interleaving Simulator
NTSTATUS CreateFuzzingThread(PTHREAD_CONTEXT Context);
VOID DestroyFuzzingThread(PTHREAD_CONTEXT Context);
VOID ThreadWorker(PVOID Parameter);
VOID SimulateThreadRace(PTHREAD_CONTEXT Context);
NTSTATUS CreateMutex(PCHAR MutexName, PHANDLE MutexHandle);
NTSTATUS ReleaseMutex(HANDLE MutexHandle);
NTSTATUS WaitForMutex(HANDLE MutexHandle, ULONG TimeoutMs);
NTSTATUS SimulateRaceCondition(ULONG RaceType, PULONG ThreadIds, ULONG ThreadCount);
NTSTATUS AddJitter(ULONG BaseDelayMs, ULONG JitterRangeMs);
NTSTATUS SetThreadPriority(PTHREAD_CONTEXT Context, ULONG Priority);
NTSTATUS SetThreadAffinity(PTHREAD_CONTEXT Context, KAFFINITY Affinity);

// Module 2: Shared Resource Mutator
NTSTATUS CreateResource(RESOURCE_TYPE ResourceType, PRESOURCE_CONTEXT Context);
NTSTATUS DestroyResource(PRESOURCE_CONTEXT Context);
NTSTATUS AccessResource(PRESOURCE_CONTEXT Context, ACCESS_TYPE AccessType);
NTSTATUS AllocateKernelPool(ULONG Size, ULONG Tag, PVOID* Address);
NTSTATUS FreeKernelPool(PVOID Address);
NTSTATUS CreateFileHandle(PCHAR FileName, PHANDLE FileHandle);
NTSTATUS WriteFile(HANDLE FileHandle, PVOID Data, ULONG Size);
NTSTATUS ReadFile(HANDLE FileHandle, PVOID Buffer, ULONG Size);
NTSTATUS CloseFile(HANDLE FileHandle);
NTSTATUS CreateRegistryKey(PCHAR KeyPath, PHANDLE KeyHandle);
NTSTATUS SetRegistryValue(HANDLE KeyHandle, PCHAR ValueName, PVOID ValueData, ULONG DataSize);
NTSTATUS CloseRegistryKey(HANDLE KeyHandle);
NTSTATUS CreateNamedPipe(PCHAR PipeName, PHANDLE PipeHandle);
NTSTATUS WritePipe(HANDLE PipeHandle, PVOID Data, ULONG Size);
NTSTATUS ReadPipe(HANDLE PipeHandle, PVOID Buffer, ULONG Size);
NTSTATUS ClosePipe(HANDLE PipeHandle);
NTSTATUS SimulateResourceRace(RESOURCE_TYPE ResourceType, PRESOURCE_CONTEXT Resources, ULONG ResourceCount);

// Module 3: Race Detector
NTSTATUS DetectRaceConditions(VOID);
NTSTATUS RecordMemoryAccess(PVOID Address, ACCESS_TYPE AccessType, ULONG Size, ULONG ThreadId);
NTSTATUS RecordLockAcquisition(PVOID LockHandle, ULONG ThreadId);
NTSTATUS RecordLockRelease(PVOID LockHandle, ULONG ThreadId);
NTSTATUS AddCoveragePoint(PVOID Address, PCHAR FunctionName);
NTSTATUS HitCoveragePoint(PVOID Address, ULONG ThreadId);
NTSTATUS GetCoverageStats(PULONG TotalPoints, PULONG HitPoints, PULONG Percentage);
NTSTATUS AnalyzeLockset(ULONG ThreadId, PVOID MemoryAddress);
NTSTATUS DetectUseAfterFree(PVOID Address, ULONG ThreadId);
NTSTATUS DetectDoubleFree(PVOID Address, ULONG ThreadId);
NTSTATUS DetectBufferOverflow(PVOID Address, ULONG Size, ULONG AllocatedSize);
NTSTATUS DetectIntegerOverflow(ULONG Value, ULONG MaxValue);
NTSTATUS DetectNullPointerDeref(PVOID Address);
NTSTATUS DetectUninitializedMemory(PVOID Address, ULONG Size);
NTSTATUS LogRaceCondition(CORRUPTION_TYPE Type, PVOID Address, ULONG ThreadId, PCHAR Description);

// Module 4: Fault Pattern Generator
NTSTATUS SynthesizeFaultPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateROPChain(PVOID Buffer, ULONG BufferSize, PVOID TargetAddress);
NTSTATUS GenerateHeapSpray(PVOID Buffer, ULONG BufferSize, PVOID TargetAddress);
NTSTATUS GenerateUseAfterFreePattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateDoubleFreePattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateHeapSprayPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateRopChainPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GeneratePrivilegeEscalationPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateCodeInjectionPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS CalculatePatternConfidence(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS ValidateFaultPattern(PFAULT_PATTERN Pattern);

// Module 5: Coverage Tracker & Feedback Loop
NTSTATUS AddInput(PVOID InputData, ULONG InputSize);
NTSTATUS GetNextInput(PVOID* InputData, PULONG InputSize);
NTSTATUS MutateInput(PVOID OriginalInput, ULONG InputSize, MUTATION_TYPE MutationType, PMUTATION_RESULT Result);
NTSTATUS UpdateMutationResult(ULONG MutationId, ULONG CoverageGained, BOOLEAN CrashInduced, BOOLEAN PatternFound);
NTSTATUS BitFlipMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result);
NTSTATUS ByteFlipMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result);
NTSTATUS ArithmeticMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result);
NTSTATUS InterestingMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result);
NTSTATUS HavocMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result);
NTSTATUS SpliceMutation(PVOID Input1, ULONG Size1, PVOID Input2, ULONG Size2, PMUTATION_RESULT Result);
NTSTATUS CalculateCoverageGain(PVOID Input, ULONG Size, PULONG CoverageGain);
NTSTATUS IsInterestingInput(PVOID Input, ULONG Size, BOOLEAN* IsInteresting);

// Utility functions
VOID LogMessage(PCHAR Format, ...);
NTSTATUS GenerateRandomData(PVOID Buffer, ULONG Size);
ULONG CalculateHash(PVOID Data, ULONG Size);
BOOLEAN IsAddressValid(PVOID Address);
VOID CleanupResources(VOID);
NTSTATUS InitializeFuzzingEngine(VOID);
VOID ShutdownFuzzingEngine(VOID);
NTSTATUS ValidateConfiguration(PFUZZING_CONFIG Config);
NTSTATUS AllocateFuzzingMemory(SIZE_T Size, ULONG Tag, PVOID* Address);
VOID FreeFuzzingMemory(PVOID Address);
NTSTATUS ProtectMemory(PVOID Address, SIZE_T Size, ULONG Protection);
NTSTATUS CreateFuzzingResources(VOID);
VOID CreateFuzzingThreads(VOID);
VOID SimulateRaceConditions(VOID);
VOID UpdateCoverage(VOID);
VOID SynthesizeFaultPatterns(VOID);
VOID UpdateStatistics(VOID);
VOID GenerateInput(PVOID* InputData, PULONG InputSize);

// Macros
#define LOG_INFO(Format, ...) LogMessage("[INFO] " Format "\n", __VA_ARGS__)
#define LOG_WARN(Format, ...) LogMessage("[WARN] " Format "\n", __VA_ARGS__)
#define LOG_ERROR(Format, ...) LogMessage("[ERROR] " Format "\n", __VA_ARGS__)
#define LOG_DEBUG(Format, ...) LogMessage("[DEBUG] " Format "\n", __VA_ARGS__)

#define ASSERT(condition) \
    if (!(condition)) { \
        LogMessage("Assertion failed: %s\n", #condition); \
        KeBugCheckEx(0xDEADBEEF, 0, 0, 0, 0); \
    }

#define SAFE_FREE(ptr) \
    if (ptr) { \
        ExFreePoolWithTag(ptr, RACE_FUZZER_TAG); \
        ptr = NULL; \
    }

#define ROUND_UP(value, alignment) \
    (((value) + (alignment) - 1) & ~((alignment) - 1))

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define IS_POWER_OF_2(value) \
    ((value) != 0 && ((value) & ((value) - 1)) == 0)

#define ALIGN_TO_PAGE(value) \
    ROUND_UP(value, PAGE_SIZE)

#define ALIGN_TO_CACHE_LINE(value) \
    ROUND_UP(value, 64)

#endif // KERNEL_FUZZER_H
